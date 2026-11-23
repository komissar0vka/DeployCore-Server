package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxArtifactSize = 2 * 1024 * 1024 * 1024
const diskReserve = 256 * 1024 * 1024

var hexDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var msiProperty = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,71}=[^\x00-\x1f]*$`)

var errArtifactIntegrity = errors.New("artifact hash or length mismatch")

type Detection struct {
	Kind        string `json:"kind"`
	ProductCode string `json:"product_code"`
	DisplayName string `json:"display_name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
}

type Manifest struct {
	Installer       string    `json:"installer"`
	Architecture    string    `json:"architecture"`
	Size            int64     `json:"size_bytes"`
	Hash            string    `json:"sha256"`
	Args            []string  `json:"args"`
	Detection       Detection `json:"detection"`
	TimeoutSeconds  int       `json:"timeout_seconds"`
	SuccessCodes    []uint32  `json:"success_codes"`
	MinWindowsBuild uint32    `json:"min_windows_build"`
	RebootRequired  bool      `json:"reboot_required"`
}

type ExecutionResult struct {
	Outcome     string  `json:"outcome"`
	ExitCode    *uint32 `json:"exit_code,omitempty"`
	Diagnostic  string  `json:"diagnostic,omitempty"`
	OutputBytes *int64  `json:"output_bytes,omitempty"`
}

type ExecutionHooks struct {
	Stage    func(string) error
	Download func(string, Manifest) error
	Start    func() error
}

type Executor func(context.Context, Assignment, Manifest, ExecutionHooks) (ExecutionResult, error)

func (m Manifest) valid() bool {
	if (m.Installer != "msi" && m.Installer != "exe") || (m.Architecture != "x64" && m.Architecture != "x86") ||
		m.Size < 1 || m.Size > maxArtifactSize || !hexDigest.MatchString(m.Hash) ||
		m.TimeoutSeconds < 1 || m.TimeoutSeconds > 86400 || len(m.Args) > 64 ||
		len(m.SuccessCodes) < 1 || len(m.SuccessCodes) > 32 {
		return false
	}
	length := 0
	for _, arg := range m.Args {
		length += len(arg)
		if len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	return length <= 8192
}

func msiArguments(operation, filename, logfile string, manifest Manifest) ([]string, error) {
	mode, target := "/i", filename
	if operation == "uninstall" {
		if manifest.Detection.Kind != "msi_product" || !deviceIDPattern.MatchString(strings.ToLower(manifest.Detection.ProductCode)) {
			return nil, fmt.Errorf("invalid MSI product code")
		}
		mode, target = "/x", "{"+manifest.Detection.ProductCode+"}"
	}
	ui := "/qn"
	properties := make([]string, 0, len(manifest.Args))
	hasUI := false
	for _, arg := range manifest.Args {
		switch strings.ToLower(arg) {
		case "/qn", "/qb":
			if hasUI {
				return nil, fmt.Errorf("multiple MSI UI flags")
			}
			ui, hasUI = strings.ToLower(arg), true
		case "/norestart":
		default:
			property, _, _ := strings.Cut(arg, "=")
			if !msiProperty.MatchString(arg) || slices.Contains([]string{"TRANSFORMS", "PATCH", "REBOOT", "REBOOTPROMPT", "ACTION", "SOURCELIST"}, property) {
				return nil, fmt.Errorf("unsupported MSI argument")
			}
			properties = append(properties, arg)
		}
	}
	args := []string{mode, target, ui, "/norestart"}
	if logfile != "" {
		args = append(args, "/L*v", logfile)
	}
	return append(args, properties...), nil
}

func verifyArtifact(destination io.Writer, source io.Reader, size int64, expected string) error {
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, size+1))
	if err != nil {
		return err
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errArtifactIntegrity
	}
	return nil
}

func (c *Client) download(ctx context.Context, path, credential, destination string, m Manifest) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Accept-Encoding", "identity")
	stream := *c.http
	stream.Timeout = 0
	response, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return StatusError(response.StatusCode)
	}
	if (response.ContentLength >= 0 && response.ContentLength != m.Size) || response.Header.Get("X-DeployCore-SHA256") != m.Hash {
		return errArtifactIntegrity
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = verifyArtifact(file, response.Body, m.Size, m.Hash)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func acceptedExit(code uint32, m Manifest) bool {
	return slices.Contains(m.SuccessCodes, code) || (m.Installer == "msi" && (code == 0 || code == 3010 || code == 1641))
}
