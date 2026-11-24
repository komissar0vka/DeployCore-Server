package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type portableReceipt struct {
	Folder string
	Hash string
	Pending string
	ShortcutHash string
}

func portableHash(path string) (string, error) {
	if err := rejectReparse(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	file, err := os.Open(path)
	if err != nil { return "", err }
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxArtifactSize+1))
	if err != nil || n > maxArtifactSize { return "", fmt.Errorf("cannot read managed file") }
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func portableDirectory(parent, child string, create bool) (string, error) {
	if !filepath.IsLocal(child) || filepath.Base(child) != child { return "", fmt.Errorf("invalid managed directory") }
	if err := rejectReparse(parent, true); err != nil { return "", err }
	path := filepath.Join(parent, child)
	if create {
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) { return "", err }
	}
	return path, rejectReparse(path, true)
}

func replacePortable(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil { return err }
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil { return err }
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func newPortableShortcut(ctx context.Context, work, executable, target string) error {
	system, err := windows.GetSystemDirectory()
	if err != nil { return err }
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	command := "$ErrorActionPreference='Stop'; $s=(New-Object -ComObject WScript.Shell).CreateShortcut(" +
		quote(target) + "); $s.TargetPath=" + quote(executable) + "; $s.WorkingDirectory=" +
		quote(filepath.Dir(executable)) + "; $s.Save()"
	launched := false
	code, _, err := runWindowsProcess(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
		[]string{"-NoProfile", "-NonInteractive", "-Command", command}, work, &launched)
	if err != nil || code != 0 { return fmt.Errorf("could not create Start menu shortcut") }
	return nil
}

func applyPortable(ctx context.Context, directory string, job Assignment, m Manifest, hooks ExecutionHooks) (ExecutionResult, error) {
	fail := func() (ExecutionResult, error) {
		return ExecutionResult{Outcome: "failed", Diagnostic: "process_error"}, nil
	}
	if !m.valid() || !filepath.IsLocal(m.Detection.Folder) { return fail() }
	ctx, cancel := context.WithTimeout(ctx, time.Duration(m.TimeoutSeconds)*time.Second)
	defer cancel()
	key := filepath.Join(directory, "portable-"+m.PackageID+".dpapi")
	var receipt portableReceipt
	err := loadProtectedJSON(key, &receipt)
	if err != nil && !errors.Is(err, os.ErrNotExist) { return fail() }
	if receipt.Folder != "" && !strings.EqualFold(receipt.Folder, m.Detection.Folder) { return fail() }
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil { return fail() }
	work := filepath.Join(directory, "deployment-"+job.AttemptID)
	if err := createPrivateDirectory(work); err != nil { return fail() }
	defer os.Remove(work)
	install := job.Operation == "install"
	managed, err := portableDirectory(root, "DeployCore Apps", install)
	if errors.Is(err, os.ErrNotExist) && !install {
		return ExecutionResult{Outcome:"already_absent", Detection:notInstalled},nil
	}
	if err != nil { return fail() }
	folder, err := portableDirectory(managed, m.Detection.Folder, install)
	if errors.Is(err, os.ErrNotExist) && !install {
		return ExecutionResult{Outcome:"already_absent", Detection:notInstalled},nil
	}
	if err != nil { return fail() }
	executable := filepath.Join(folder,"application.exe")
	hash, err := portableHash(executable)
	if err != nil || (hash != "" && hash != receipt.Hash && hash != receipt.Pending) { return fail() }
	programs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil { return fail() }
	shortcutFolder, err := portableDirectory(programs, "DeployCore Apps", install && m.Detection.Shortcut)
	if err != nil && !errors.Is(err, os.ErrNotExist) { return fail() }
	shortcut := filepath.Join(shortcutFolder, m.PackageID+".lnk")
	linkHash, err := portableHash(shortcut)
	if err != nil || (linkHash != "" && linkHash != receipt.ShortcutHash) { return fail() }
	if install && hash == m.Hash && (linkHash != "") == m.Detection.Shortcut {
		return ExecutionResult{Outcome:"already_installed", Detection:installed},nil
	}
	if !install && hash == "" && linkHash == "" {
		return ExecutionResult{Outcome:"already_absent", Detection:notInstalled},nil
	}
	staged := ""
	if install && hash != m.Hash {
		staged = filepath.Join(folder,"pending-"+job.AttemptID+".exe")
		if err := hooks.Stage("downloading"); err != nil { return ExecutionResult{},err }
		download := filepath.Join(work,"portable.exe")
		defer os.Remove(download)
		if err := hooks.Download(download,m); err != nil { return ExecutionResult{},err }
		from, err := os.Open(download)
		if err != nil { return fail() }
		defer from.Close()
		to, err := os.OpenFile(staged,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
		if err != nil { return fail() }
		defer os.Remove(staged)
		err = verifyArtifact(to,from,m.Size,m.Hash)
		if err == nil { err = to.Sync() }
		closeErr := to.Close()
		if err != nil || closeErr != nil { return fail() }
	}
	if err := hooks.Start(); err != nil { return ExecutionResult{},err }
	started := true
	unknownFailure := func() (ExecutionResult,error) {
		return ExecutionResult{Outcome:"unknown", Diagnostic:"process_error", ProcessStarted:&started},nil
	}
	if install {
		receipt.Folder, receipt.Pending = m.Detection.Folder, m.Hash
		if err := saveProtectedJSON(key,receipt);err != nil { return unknownFailure() }
		if staged != "" && replacePortable(staged,executable) != nil { return unknownFailure() }
		if m.Detection.Shortcut && linkHash == "" {
			link := filepath.Join(work,"portable.lnk")
			defer os.Remove(link)
			if err := newPortableShortcut(ctx,work,executable,link); err != nil { return unknownFailure() }
			receipt.ShortcutHash,err = portableHash(link)
			if err != nil || receipt.ShortcutHash == "" || saveProtectedJSON(key,receipt) != nil || replacePortable(link,shortcut) != nil { return unknownFailure() }
		} else if !m.Detection.Shortcut && linkHash != "" {
			if err := os.Remove(shortcut);err != nil { return unknownFailure() }
			receipt.ShortcutHash = ""
		}
		_ = hooks.Stage("verifying")
		installedHash, err := portableHash(executable)
		if err != nil || installedHash != m.Hash { return unknownFailure() }
		receipt.Hash, receipt.Pending = m.Hash, ""
		if err := saveProtectedJSON(key,receipt); err != nil { return unknownFailure() }
		return ExecutionResult{Outcome:"succeeded", Detection:installed, ProcessStarted:&started},nil
	}
	if hash != "" && os.Remove(executable) != nil { return unknownFailure() }
	if linkHash != "" && os.Remove(shortcut) != nil { return unknownFailure() }
	if err := os.Remove(key); err != nil && !errors.Is(err,os.ErrNotExist) { return unknownFailure() }
	return ExecutionResult{Outcome:"succeeded",Detection:notInstalled,ProcessStarted:&started},nil
}
