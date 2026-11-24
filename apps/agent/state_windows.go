package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const stateFile = "state.dpapi"

func agentDirectory() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "DeployCore"), nil
}

func createPrivateDirectory(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	err = windows.CreateDirectory(name, &attributes)
	if err == nil {
		return nil
	}
	if err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	return rejectReparse(path, true)
}

func rejectReparse(path string, directory bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if flags&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(flags&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fmt.Errorf("unexpected file type: %s", path)
	}
	return nil
}

func crypt(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty DPAPI input")
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&input, nil, nil, 0, nil,
			windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

func atomicWrite(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".deploycore-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	from, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func saveProtectedJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	protected, err := crypt(encoded, true)
	if err != nil {
		return err
	}
	return atomicWrite(path, protected)
}

func loadProtectedJSON(path string, value any) error {
	if err := rejectReparse(path, false); err != nil {
		return err
	}
	protected, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data, err := crypt(protected, false)
	if err != nil {
		return err
	}
	defer clear(data)
	return json.Unmarshal(data, value)
}

func saveState(directory string, state State) error {
	return saveProtectedJSON(filepath.Join(directory, stateFile), state)
}

func loadState(directory string) (State, error) {
	if err := rejectReparse(directory, true); err != nil {
		return State{}, err
	}
	var state State
	if err := loadProtectedJSON(filepath.Join(directory, stateFile), &state); err != nil {
		return State{}, err
	}
	if !deviceIDPattern.MatchString(state.DeviceID) || !validToken(state.Credential) ||
		(state.PendingToken != "" && !validToken(state.PendingToken)) {
		return State{}, fmt.Errorf("invalid agent state")
	}
	return state, nil
}

func loadJobTrust(directory string) (*JobTrust, jobReplay, error) {
	policyPath := filepath.Join(directory, "job-trust.json")
	replayPath := filepath.Join(directory, "job-replay.dpapi")
	var replay jobReplay
	replayErr := loadProtectedJSON(replayPath, &replay)
	if replayErr != nil && !errors.Is(replayErr, os.ErrNotExist) {
		return nil, nil, replayErr
	}
	if err := rejectReparse(policyPath, false); err != nil {
		if errors.Is(err, os.ErrNotExist) && errors.Is(replayErr, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	file, err := os.Open(policyPath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil {
		return nil, nil, err
	}
	var trust JobTrust
	if len(raw) > 256*1024 || !uniqueJSONKeys(raw) || json.Unmarshal(raw, &trust) != nil {
		return nil, nil, fmt.Errorf("invalid job trust policy")
	}
	if err := trust.validate(); err != nil {
		return nil, nil, err
	}
	if errors.Is(replayErr, os.ErrNotExist) {
		replay = make(jobReplay)
		if err := saveProtectedJSON(replayPath, replay); err != nil {
			return nil, nil, err
		}
	}
	if replay == nil || len(replay) > maxReplayEntries {
		return nil, nil, fmt.Errorf("invalid replay store")
	}
	return &trust, replay, nil
}
