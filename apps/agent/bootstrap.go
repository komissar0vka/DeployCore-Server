package main

import (
	"encoding/json"
	"fmt"
	"io"
)

const maxBootstrapBytes = 128 * 1024

type enrollmentBootstrap struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	CA     string `json:"ca"`
}

func parseBootstrap(source io.Reader) (enrollmentBootstrap, error) {
	raw, err := io.ReadAll(io.LimitReader(source, maxBootstrapBytes+1))
	if err != nil || len(raw) > maxBootstrapBytes {
		return enrollmentBootstrap{}, fmt.Errorf("could not read MSI enrollment configuration")
	}
	var config enrollmentBootstrap
	if err := json.Unmarshal(raw, &config); err != nil || !validToken(config.Token) {
		return enrollmentBootstrap{}, fmt.Errorf("invalid MSI enrollment configuration")
	}
	config.Server, err = secureOrigin(config.Server)
	if err != nil {
		return enrollmentBootstrap{}, fmt.Errorf("invalid MSI server address")
	}
	return config, nil
}
