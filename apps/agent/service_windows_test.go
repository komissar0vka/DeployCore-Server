package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestPackagedAgentService(t *testing.T) {
	exe := os.Getenv("DEPLOYCORE_TEST_PACKAGED_AGENT")
	if exe == "" {
		t.Skip("set DEPLOYCORE_TEST_PACKAGED_AGENT on a clean elevated Windows runner")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("test requires administrator rights")
	}
	directory, err := agentDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("test requires a clean host without DeployCore service files")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(serviceName); !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		if existing != nil {
			existing.Close()
		}
		t.Fatal("test requires a clean host without a DeployCore service")
	}

	token, err := randomCredential()
	if err != nil {
		t.Fatal(err)
	}
	legacyExe, initialVersion := exe, version
	if path := os.Getenv("DEPLOYCORE_TEST_LEGACY_AGENT"); path != "" {
		legacyExe, initialVersion = path, "0.3.8"
	}
	var mu sync.Mutex
	var id, credential string
	enrolled, inventory, pulse := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	signal := func(event chan struct{}) {
		select {
		case event <- struct{}{}:
		default:
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/health/ready":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/agent/enroll":
			var input Enrollment
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&input) != nil ||
				input.EnrollmentToken != token || !deviceIDPattern.MatchString(input.InstallationID) ||
				!validToken(input.Credential) || input.Heartbeat.Hostname == "" || input.Heartbeat.AgentVersion != initialVersion {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			id, credential = input.InstallationID, input.Credential
			signal(enrolled)
			_ = json.NewEncoder(w).Encode(Connection{DeviceID: id, HeartbeatSeconds: 60})
		default:
			if credential == "" || r.Header.Get("Authorization") != "Bearer "+credential {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch r.URL.Path {
			case "/api/v1/agent/" + id + "/inventory":
				var data Inventory
				if r.Method != http.MethodPut || json.NewDecoder(r.Body).Decode(&data) != nil ||
					len(data.Hardware.CPUs) == 0 || data.Hardware.RAM == 0 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				signal(inventory)
			case "/api/v1/agent/" + id + "/heartbeat":
				_ = json.NewEncoder(w).Encode(Connection{DeviceID: id, HeartbeatSeconds: 60})
				signal(pulse)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	migration := os.Getenv("DEPLOYCORE_TEST_MIGRATION_SCRIPT")
	if migration != "" {
		_ = server.Listener.Close()
		server.Listener, err = net.Listen("tcp", "127.0.0.1:17777")
		if err != nil {
			t.Fatal(err)
		}
	}
	server.StartTLS()
	defer server.Close()

	file := filepath.Join(t.TempDir(), "trust.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	rejected := exec.Command(exe, "install", "--server", server.URL)
	rejected.Stdin = strings.NewReader(token)
	if err := rejected.Run(); err == nil {
		t.Fatal("installer accepted an untrusted certificate")
	}
	t.Cleanup(func() {
		_ = exec.Command(exe, "uninstall").Run()
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	install := exec.Command(legacyExe, "install", "--server", server.URL, "--ca", file)
	install.Stdin = strings.NewReader(token)
	if output, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install failed: %v: %s", err, output)
	}
	wait := func(label string, event <-chan struct{}) {
		t.Helper()
		select {
		case <-event:
		case <-time.After(55 * time.Second):
			t.Fatalf("agent did not send %s", label)
		}
	}
	wait("enrollment", enrolled)
	wait("inventory", inventory)
	service, err := manager.OpenService(serviceName)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil || config.StartType != mgr.StartAutomatic {
		t.Fatal("service is not configured to start automatically")
	}
	if err := stopService(service); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pulse:
	default:
	}
	if status, err := service.Query(); err != nil || status.State != svc.Stopped {
		t.Fatal("service did not stop")
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	wait("heartbeat after restart with the original credential", pulse)
	select {
	case <-enrolled:
		t.Fatal("service enrolled again after restart")
	default:
	}
	if migration != "" {
		_ = service.Close()
		before, err := loadState(directory)
		if err != nil {
			t.Fatal(err)
		}
		policy := filepath.Join(directory, "agent-update-publishers.json")
		testPins := []byte(`{"certificate_sha256":["` + strings.Repeat("a", 64) + `"]}`)
		if err := os.WriteFile(policy, testPins, 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(policy) })
		unsigned := os.Getenv("DEPLOYCORE_TEST_MIGRATION_CURRENT")
		payload, err := os.ReadFile(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		reject := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-File", migration,
			"-Msi", unsigned, "-Sha256", fmt.Sprintf("%x", sha256.Sum256(payload)))
		if output, err := reject.CombinedOutput(); err == nil || !strings.Contains(string(output), "valid Authenticode signature") {
			t.Fatalf("strict publisher policy did not reject unsigned update: %v: %s", err, output)
		}
		unchanged, err := loadState(directory)
		if err != nil || !reflect.DeepEqual(before, unchanged) {
			t.Fatal("rejected update changed protected state")
		}
		if err := os.Remove(policy); err != nil {
			t.Fatal(err)
		}
		for index, key := range []string{"DEPLOYCORE_TEST_MIGRATION_PREVIOUS", "DEPLOYCORE_TEST_MIGRATION_CURRENT"} {
			msi := os.Getenv(key)
			signed := os.Getenv("DEPLOYCORE_TEST_MIGRATION_SIGNED")
			if index == 1 && signed != "" {
				msi = signed
				publisher := os.Getenv("DEPLOYCORE_TEST_PUBLISHER_SHA256")
				if len(publisher) != 64 {
					t.Fatal("invalid hosted publisher fingerprint")
				}
				policyData := []byte(`{"certificate_sha256":["` + publisher + `"]}`)
				if err := os.WriteFile(policy, policyData, 0600); err != nil {
					t.Fatal(err)
				}
			}
			binary, err := os.ReadFile(msi)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = exec.Command("msiexec.exe", "/x", msi, "/qn", "/norestart").Run() })
			select {
			case <-pulse:
			default:
			}
			command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-File", migration,
				"-Msi", msi, "-Sha256", fmt.Sprintf("%x", sha256.Sum256(binary)))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("MSI transition failed: %v: %s", err, output)
			}
			wait("heartbeat after MSI upgrade", pulse)
			expectedVersion := version
			if index == 0 {
				expectedVersion = initialVersion
			}
			managed := filepath.Join(filepath.Dir(directory), "DeployCore Managed Agent", exeName)
			output, err := exec.Command(managed, "version").Output()
			if err != nil || strings.TrimSpace(string(output)) != expectedVersion {
				t.Fatalf("installed MSI version: got %q, want %q, error %v", output, expectedVersion, err)
			}
			after, err := loadState(directory)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("MSI changed the stored registration, certificate, or credential")
			}
			select {
			case <-enrolled:
				t.Fatal("MSI enrolled an existing agent a second time")
			default:
			}
		}
	}

}
