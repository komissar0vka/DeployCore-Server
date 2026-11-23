package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsExecutor(directory string) Executor {
	return func(ctx context.Context, job Assignment, m Manifest, hooks ExecutionHooks) (ExecutionResult, error) {
		fail := func(code string) (ExecutionResult, error) {
			return ExecutionResult{Outcome: "failed", Diagnostic: code}, nil
		}
		if windows.RtlGetVersion().BuildNumber < m.MinWindowsBuild || (m.Architecture == "x64" && osInfo().Architecture != "amd64") {
			return fail("platform_unsupported")
		}
		if err := hooks.Stage("checking"); err != nil {
			return ExecutionResult{}, err
		}
		installed, err := detectWindows(ctx, m.Detection)
		if err != nil {
			return fail("detection_failed")
		}
		if installed && job.Operation == "install" {
			return ExecutionResult{Outcome: "already_installed"}, nil
		}
		if !installed && job.Operation == "uninstall" {
			return ExecutionResult{Outcome: "already_absent"}, nil
		}

		// The attempt UUID is canonicalized before this function. A deterministic private workspace
		// can be cleaned before launch after a download interruption, including a service restart.
		work := filepath.Join(directory, "deployment-"+job.AttemptID)
		if err := createPrivateDirectory(work); err != nil {
			return fail("process_error")
		}
		defer removeWorkspace(work)
		path := filepath.Join(work, "package."+m.Installer)
		logfile := ""
		if os.Getenv("DEPLOYCORE_LOCAL_MSI_LOG") == "1" {
			logfile = filepath.Join(work, "msi.log")
		}
		if err := removeWorkspaceFiles(work); err != nil {
			return fail("process_error")
		}
		program, args := path, m.Args
		if m.Installer == "msi" {
			system, err := windows.GetSystemDirectory()
			if err != nil {
				return fail("process_error")
			}
			program = filepath.Join(system, "msiexec.exe")
			args, err = msiArguments(job.Operation, path, logfile, m)
			if err != nil {
				return fail("manifest_invalid")
			}
		}
		if m.Installer != "msi" || job.Operation != "uninstall" {
			wide, err := windows.UTF16PtrFromString(work)
			if err != nil {
				return fail("process_error")
			}
			var free uint64
			if err := windows.GetDiskFreeSpaceEx(wide, &free, nil, nil); err != nil || free < uint64(m.Size)+diskReserve {
				return fail("insufficient_space")
			}
			if err := hooks.Stage("downloading"); err != nil {
				return ExecutionResult{}, err
			}
			if err := hooks.Download(path, m); err != nil {
				if errors.Is(err, errArtifactIntegrity) {
					return fail("hash_mismatch")
				}
				var status StatusError
				if errors.As(err, &status) && status >= 400 && status < 500 && status != 401 {
					return fail("download_failed")
				}
				return ExecutionResult{}, err
			}
		}
		if err := hooks.Start(); err != nil {
			return ExecutionResult{}, err
		}
		timeout, cancel := context.WithTimeout(ctx, time.Duration(m.TimeoutSeconds)*time.Second)
		code, bytes, err := runWindowsProcess(timeout, program, args, work)
		cancel()
		if info, statErr := os.Stat(logfile); statErr == nil {
			bytes += info.Size()
		}
		if err != nil {
			diagnostic := "process_error"
			if errors.Is(err, context.DeadlineExceeded) {
				diagnostic = "timeout"
			}
			return ExecutionResult{Outcome: "unknown", Diagnostic: diagnostic, OutputBytes: &bytes}, nil
		}
		_ = hooks.Stage("verifying")
		result := ExecutionResult{Outcome: "failed", ExitCode: &code, OutputBytes: &bytes}
		if !acceptedExit(code, m) {
			result.Diagnostic = "installer_error"
			return result, nil
		}
		present, err := detectWindows(ctx, m.Detection)
		if err != nil || present != (job.Operation == "install") {
			result.Diagnostic = "detection_failed"
			if err != nil || code == 3010 || code == 1641 || m.RebootRequired {
				result.Outcome = "unknown"
			}
			return result, nil
		}
		result.Outcome = "succeeded"
		if code == 3010 || code == 1641 || m.RebootRequired {
			result.Outcome = "reboot_required"
		}
		return result, nil
	}
}

func removeWorkspaceFiles(work string) error {
	for _, name := range []string{"package.exe", "package.msi", "msi.log"} {
		if err := os.Remove(filepath.Join(work, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func removeWorkspace(work string) {
	_ = removeWorkspaceFiles(work)
	_ = os.Remove(work)
}

type byteCounter struct{ bytes atomic.Int64 }

func (c *byteCounter) Write(data []byte) (int, error) {
	c.bytes.Add(int64(len(data)))
	return len(data), nil
}

type jobAccounting struct {
	user, kernel, periodUser, periodKernel int64
	faults, total, active, terminated      uint32
}

func runWindowsProcess(ctx context.Context, exe string, args []string, directory string) (uint32, int64, error) {
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, 0, err
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, args...)))
	if err != nil {
		return 0, 0, err
	}
	dir, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, 0, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, 0, err
	}

	read, write, err := os.Pipe()
	if err != nil {
		return 0, 0, err
	}
	defer read.Close()
	defer write.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		return 0, 0, err
	}
	defer null.Close()
	handles := [2]windows.Handle{windows.Handle(write.Fd()), windows.Handle(null.Fd())}
	for _, handle := range handles {
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return 0, 0, err
		}
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, 0, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)); err != nil {
		return 0, 0, err
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attributes.List(),
		StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES,
			StdInput: handles[1], StdOutput: handles[0], StdErr: handles[0]}}
	var process windows.ProcessInformation
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if err := windows.CreateProcess(app, command, nil, nil, true,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT, nil, dir, &startup.StartupInfo, &process); err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	_ = write.Close()
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		return 0, 0, err
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return 0, 0, err
	}

	var count byteCounter
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(&count, read); close(drained) }()
	defer func() { _ = read.Close(); <-drained }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var accounting jobAccounting
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
			return 0, count.bytes.Load(), err
		}
		if accounting.active == 0 {
			var code uint32
			err := windows.GetExitCodeProcess(process.Process, &code)
			select {
			case <-drained:
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			return code, count.bytes.Load(), err
		}
		select {
		case <-ctx.Done():
			_ = windows.TerminateJobObject(job, 1)
			return 0, count.bytes.Load(), ctx.Err()
		case <-ticker.C:
		}
	}
}

func detectWindows(ctx context.Context, rule Detection) (bool, error) {
	switch rule.Kind {
	case "registry_software":
		list, err := machineSoftware(ctx)
		if err != nil {
			return false, err
		}
		for item := range list {
			if strings.EqualFold(item.Name, rule.DisplayName) && item.Version == rule.Version {
				return true, nil
			}
		}
		return false, nil
	case "msi_product":
		if !deviceIDPattern.MatchString(strings.ToLower(rule.ProductCode)) {
			return false, fmt.Errorf("invalid product code")
		}
		code := windows.StringToUTF16Ptr("{" + rule.ProductCode + "}")
		result, _, _ := windows.NewLazySystemDLL("msi.dll").NewProc("MsiQueryProductStateW").Call(uintptr(unsafe.Pointer(code)))
		switch int32(result) {
		case 3, 5:
			return true, nil
		case -1, 1, 2:
			return false, nil
		default:
			return false, fmt.Errorf("indeterminate product state")
		}
	case "file_exists", "file_version":
		return detectFile(rule)
	default:
		return false, fmt.Errorf("unknown detection rule")
	}
}

func detectFile(rule Detection) (bool, error) {
	path := rule.Path
	if len(path) < 4 || path[1:3] != `:\` || strings.ContainsAny(path[2:], ":/") || filepath.Clean(path) != path ||
		windows.GetDriveType(windows.StringToUTF16Ptr(path[:3])) != windows.DRIVE_FIXED {
		return false, fmt.Errorf("file detection requires a fixed local volume")
	}
	for parent := filepath.Dir(path); len(parent) > 3; parent = filepath.Dir(parent) {
		if err := rejectReparse(parent, true); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
	}
	if err := rejectReparse(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if rule.Kind == "file_exists" {
		return true, nil
	}
	var ignored windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &ignored)
	if err != nil || size < 1 || size > 1024*1024 {
		return false, fmt.Errorf("cannot read version resource size")
	}
	data := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&data[0])); err != nil {
		return false, err
	}
	var value unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&data[0]), `\`, unsafe.Pointer(&value), &length); err != nil || length < 16 || value == nil {
		return false, fmt.Errorf("invalid version resource")
	}
	fixed := (*[4]uint32)(value)
	if fixed[0] != 0xfeef04bd {
		return false, fmt.Errorf("invalid version signature")
	}
	versionString := fmt.Sprintf("%d.%d.%d.%d", fixed[2]>>16, fixed[2]&65535, fixed[3]>>16, fixed[3]&65535)
	return versionString == rule.Version, nil
}
