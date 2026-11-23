package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var tickCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

const hardwareScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$processors = @(Get-CimInstance -ClassName Win32_Processor | Select-Object -First 64 | ForEach-Object {
    @{model=[string]$_.Name; cores=[int]$_.NumberOfCores; threads=[int]$_.NumberOfLogicalProcessors}
})
$system = Get-CimInstance -ClassName Win32_ComputerSystem
$volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3 OR DriveType=2' |
    Where-Object { $_.Size -gt 0 } | Select-Object -First 26 | ForEach-Object {
    @{letter=[string]$_.DeviceID; size_bytes=[uint64]$_.Size; free_bytes=[uint64]$_.FreeSpace; filesystem=[string]$_.FileSystem; label=[string]$_.VolumeName}
})
@{manufacturer=[string]$system.Manufacturer; model=[string]$system.Model; cpus=$processors; ram_bytes=[uint64]$system.TotalPhysicalMemory; disks=$volumes} | ConvertTo-Json -Depth 4 -Compress
`

func osInfo() OSInfo {
	info := windows.RtlGetVersion()
	name := fmt.Sprintf("Windows %d.%d.%d", info.MajorVersion, info.MinorVersion, info.BuildNumber)
	return OSInfo{Version: name, Build: fmt.Sprint(info.BuildNumber), Architecture: runtime.GOARCH}
}

func networkInventory() ([]NetworkInterface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]NetworkInterface, 0, min(len(all), 128))
	for _, item := range all {
		if item.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := clean(item.Name, 253)
		if name == "" {
			continue
		}
		addresses, err := item.Addrs()
		if err != nil {
			return nil, err
		}
		ips := make([]string, 0, min(len(addresses), 64))
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil {
				ips = append(ips, prefix.Addr().Unmap().String())
			}
			if len(ips) == 64 {
				break
			}
		}
		sort.Strings(ips)
		out = append(out, NetworkInterface{Name: name, IPs: ips, MAC: item.HardwareAddr.String()})
		if len(out) == 128 {
			break
		}
	}
	return out, nil
}

func collectHeartbeat() (Heartbeat, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return Heartbeat{}, err
	}
	fqdn := ""
	var dnsName [256]uint16
	size := uint32(len(dnsName))
	if windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &dnsName[0], &size) == nil {
		fqdn = clean(windows.UTF16ToString(dnsName[:]), 253)
	}
	networkName, domainJoined := "", false
	var joinName *uint16
	var joinType uint32
	if windows.NetGetJoinInformation(nil, &joinName, &joinType) == nil && joinName != nil {
		networkName = clean(windows.UTF16PtrToString(joinName), 253)
		domainJoined = joinType == 3
		windows.NetApiBufferFree((*byte)(unsafe.Pointer(joinName)))
	}
	interfaces, err := networkInventory()
	if err != nil {
		return Heartbeat{}, err
	}
	unique := make(map[string]struct{})
	for _, item := range interfaces {
		for _, ip := range item.IPs {
			unique[ip] = struct{}{}
		}
	}
	ips := make([]string, 0, len(unique))
	for ip := range unique {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	ticks, _, _ := tickCount.Call()
	return Heartbeat{
		Hostname: clean(hostname, 253), FQDN: fqdn, NetworkName: networkName, DomainJoined: domainJoined,
		IPs: ips[:min(len(ips), 64)], OSVersion: osInfo().Version, AgentVersion: version, Uptime: uint64(ticks) / 1000,
	}, nil
}

func encodedScript(script string) string {
	var bytes []byte
	for _, char := range utf16.Encode([]rune(script)) {
		bytes = binary.LittleEndian.AppendUint16(bytes, char)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func collectInventory(parent context.Context) (Inventory, error) {
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return Inventory{}, err
	}
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.CommandContext(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
		"-EncodedCommand", encodedScript(hardwareScript))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	data, err := command.Output()
	if err != nil {
		return Inventory{}, fmt.Errorf("collect local CIM inventory: %w", err)
	}
	var hardware Hardware
	if err := json.Unmarshal(data, &hardware); err != nil {
		return Inventory{}, fmt.Errorf("invalid local CIM inventory")
	}
	if len(hardware.CPUs) == 0 {
		return Inventory{}, fmt.Errorf("local CIM inventory has no processors")
	}
	for i := range hardware.CPUs {
		cpu := &hardware.CPUs[i]
		cpu.Model = clean(cpu.Model, 240)
		if cpu.Model == "" {
			cpu.Model = "Unknown CPU"
		}
		cpu.Cores = max(1, cpu.Cores)
		cpu.Threads = max(cpu.Cores, cpu.Threads)
	}
	if hardware.Disks == nil {
		hardware.Disks = []Disk{}
	}
	for i := range hardware.Disks {
		hardware.Disks[i].Letter = strings.ToUpper(hardware.Disks[i].Letter)
	}
	sort.Slice(hardware.Disks, func(i, j int) bool { return hardware.Disks[i].Letter < hardware.Disks[j].Letter })
	hardware.OS = osInfo()
	hardware.Manufacturer = clean(hardware.Manufacturer, 253)
	hardware.Model = clean(hardware.Model, 253)
	for index := range hardware.Disks {
		disk := &hardware.Disks[index]
		disk.Filesystem = clean(disk.Filesystem, 253)
		disk.Label = clean(disk.Label, 253)
	}
	hardware.Interfaces, err = networkInventory()
	if err != nil {
		return Inventory{}, err
	}
	software, err := installedSoftware(ctx)
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Hardware: hardware, Software: software}, nil
}

func addRegistrySoftware(ctx context.Context, root registry.Key, path string, view uint32, out map[Software]struct{}) error {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|view)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entry, err := registry.OpenKey(key, name, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		displayName, _, _ := entry.GetStringValue("DisplayName")
		versionName, _, _ := entry.GetStringValue("DisplayVersion")
		publisher, _, _ := entry.GetStringValue("Publisher")
		entry.Close()
		item := Software{Name: clean(displayName, 240), Version: clean(versionName, 120), Publisher: clean(publisher, 200)}
		if item.Name != "" {
			out[item] = struct{}{}
		}
	}
	return nil
}

func machineSoftware(ctx context.Context) (map[Software]struct{}, error) {
	items := make(map[Software]struct{})
	views := []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY}
	for _, view := range views {
		if err := addRegistrySoftware(ctx, registry.LOCAL_MACHINE, uninstallKey, view, items); err != nil {
			return nil, fmt.Errorf("read machine uninstall registry: %w", err)
		}
	}
	return items, nil
}

func installedSoftware(ctx context.Context) ([]Software, error) {
	items, err := machineSoftware(ctx)
	if err != nil {
		return nil, err
	}
	views := []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY}
	profiles, err := registry.USERS.ReadSubKeyNames(-1)
	if err == nil {
		for _, profile := range profiles {
			if strings.HasSuffix(profile, "_Classes") ||
				(!strings.HasPrefix(profile, "S-1-5-21-") && !strings.HasPrefix(profile, "S-1-12-1-")) {
				continue
			}
			for _, view := range views {
				// Only loaded profiles are optional sources.
				_ = addRegistrySoftware(ctx, registry.USERS, filepath.Join(profile, uninstallKey), view, items)
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	out := make([]Software, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Publisher < out[j].Publisher
	})
	return out[:min(len(out), 2000)], nil
}
