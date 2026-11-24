package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func loadMSIState(directory string) (State, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return State{}, err
	}
	installed := filepath.Join(root, "DeployCore Managed Agent")
	executable, err := os.Executable()
	if err != nil || !strings.EqualFold(executable, filepath.Join(installed, exeName)) {
		return State{}, fmt.Errorf("unexpected managed MSI installation directory")
	}
	if err := rejectReparse(installed, true); err != nil {
		return State{}, err
	}
	if err := createPrivateDirectory(directory); err != nil {
		return State{}, err
	}
	path := filepath.Join(installed, "enrollment.json")
	state, err := loadState(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	if err := rejectReparse(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) && state.DeviceID != "" {
			return state, nil
		}
		return State{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	config, err := parseBootstrap(file)
	file.Close()
	if err != nil {
		return State{}, err
	}
	if _, err := newClient(config.Server, []byte(config.CA)); err != nil {
		return State{}, err
	}
	if state.DeviceID == "" {
		state, err = enrollmentState(config.Server, []byte(config.CA), "", config.Token)
		if err != nil {
			return State{}, err
		}
	} else if state.Server != config.Server {
		return State{}, fmt.Errorf("saved registration uses a different server")
	}

	if err := saveState(directory, state); err != nil {
		return State{}, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, fmt.Errorf("could not remove MSI enrollment configuration")
	}
	return state, nil
}
