package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWinScanPortableLifecycle(t *testing.T) {
	sample, update := os.Getenv("DEPLOYCORE_TEST_PORTABLE_EXE"), os.Getenv("DEPLOYCORE_TEST_PORTABLE_UPDATE")
	if sample == "" || update == "" {
		t.Skip("publisher EXEs are supplied by the elevated Windows CI job")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("portable lifecycle requires an elevated runner")
	}
	id, err := installationID()
	if err != nil {
		t.Fatal(err)
	}
	slug := "WinScan2PDF " + id[:8]
	agent := t.TempDir()
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	programs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "DeployCore Apps", slug)
	exe := filepath.Join(dest, "application.exe")
	link := filepath.Join(programs, "DeployCore Apps", slug+".lnk")
	t.Cleanup(func() {
		_ = os.Remove(link)
		_ = os.RemoveAll(dest)
	})
	action := func(op, path string) ExecutionResult {
		t.Helper()
		payload, err := os.ReadFile(path)
		if err != nil || len(payload) < 2 || string(payload[:2]) != "MZ" {
			t.Fatalf("invalid vendor fixture: %v", err)
		}
		attempt, err := installationID()
		if err != nil {
			t.Fatal(err)
		}
		manifest := Manifest{
			Installer: "portable", PackageID: id, Architecture: "x86", Size: int64(len(payload)),
			Hash: fmt.Sprintf("%x", sha256.Sum256(payload)), Detection: Detection{Kind: "portable_file", Folder: slug, Shortcut: true},
			TimeoutSeconds: 30, SuccessCodes: []uint32{0},
		}
		result, err := applyPortable(context.Background(), agent, Assignment{Operation: op, AttemptID: attempt}, manifest,
			ExecutionHooks{
				Stage: func(string) error { return nil }, Start: func() error { return nil },
				Download: func(destination string, _ Manifest) error {
					in, err := os.Open(path)
					if err != nil {
						return err
					}
					defer in.Close()
					out, err := os.Create(destination)
					if err != nil {
						return err
					}
					defer out.Close()
					_, err = io.Copy(out, in)
					return err
				},
			})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if actual := action("install", sample); actual.Outcome != "succeeded" || actual.Detection != installed {
		t.Fatalf("install failed: %+v", actual)
	}
	if _, err := os.Stat(link); err != nil {
		t.Fatal(err)
	}
	if actual := action("install", sample); actual.Outcome != "already_installed" {
		t.Fatalf("installed detection failed: %+v", actual)
	}
	if actual := action("install", update); actual.Outcome != "succeeded" {
		t.Fatalf("update failed: %+v", actual)
	}
	userFile := filepath.Join(dest, "settings.ini")
	if err := os.WriteFile(userFile, []byte("Keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if actual := action("uninstall", update); actual.Outcome != "succeeded" || actual.Detection != notInstalled {
		t.Fatalf("removal failed: %+v", actual)
	}
	for _, file := range []string{exe, link} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("owned artifact still exists: %s", file)
		}
	}
	if bytes, err := os.ReadFile(userFile); err != nil || string(bytes) != "Keep me" {
		t.Fatal("uninstall changed an unrelated file")
	}
}
