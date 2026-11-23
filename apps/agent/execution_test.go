package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMSIArgumentsAreExplicit(t *testing.T) {
	manifest := Manifest{Args: []string{"/qb", "INSTALLDIR=C:\\Program Files\\Vendor", "/norestart"},
		Detection: Detection{Kind: "msi_product", ProductCode: "11111111-1111-4111-8111-111111111111"}}
	args, err := msiArguments("uninstall", "package.msi", "msi.log", manifest)
	want := []string{"/x", "{11111111-1111-4111-8111-111111111111}", "/qb", "/norestart", "/L*v", "msi.log", "INSTALLDIR=C:\\Program Files\\Vendor"}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected arguments: %v, %v", args, err)
	}
	for _, unsafe := range []string{"/i", "/forcerestart", "TRANSFORMS=unapproved.mst", "REBOOT=Force"} {
		manifest.Args = []string{unsafe}
		if _, err := msiArguments("install", "package.msi", "msi.log", manifest); err == nil {
			t.Fatalf("accepted forbidden argument %q", unsafe)
		}
	}
}

func TestDownloadHashLengthAndBound(t *testing.T) {
	data := []byte("fixture")
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	var out bytes.Buffer
	if err := verifyArtifact(&out, bytes.NewReader(data), int64(len(data)), hash); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("valid artifact failed")
	}
	for _, bad := range [][]byte{[]byte("broken!"), []byte("short"), bytes.Repeat([]byte("x"), 100)} {
		out.Reset()
		if err := verifyArtifact(&out, bytes.NewReader(bad), int64(len(data)), hash); !errors.Is(err, errArtifactIntegrity) {
			t.Fatalf("bad artifact accepted: %v", err)
		}
		if out.Len() > len(data)+1 {
			t.Fatal("size limit was exceeded")
		}
	}
}

func TestExecutionLostStartDoesNotRetryProcess(t *testing.T) {
	ctx := context.Background()
	state := testState(t, "https://example.test")
	job := Assignment{TargetID: "11111111-1111-4111-8111-111111111111", AttemptID: "22222222-2222-4222-8222-222222222222",
		VersionID: "33333333-3333-4333-8333-333333333333", Operation: "install", Mode: "execute_v1"}
	var starts, executions atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/poll"):
			if r.Header.Get("X-DeployCore-Capabilities") != "execute_v1" {
				t.Error("execution capability is missing")
			}
			_ = json.NewEncoder(w).Encode(map[string]Assignment{"assignment": job})
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			_, _ = io.WriteString(w, `{"cancel_requested":false}`)
		case strings.HasSuffix(r.URL.Path, "/manifest"):
			_ = json.NewEncoder(w).Encode(Manifest{Installer: "msi", Architecture: "x64", Hash: strings.Repeat("a", 64),
				Size: 1, TimeoutSeconds: 300, SuccessCodes: []uint32{0}})
		case strings.HasSuffix(r.URL.Path, "/start"):
			starts.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasSuffix(r.URL.Path, "/result"):
			var result ExecutionResult
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil || result.Outcome != "unknown" {
				t.Error("lost start did not become unknown")
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	var saved JobJournal
	transport := JobTransport{client: trustedClient(t, server), state: state, log: log.New(io.Discard, "", 0),
		save: func(value JobJournal) error { saved = value; return nil },
		execute: func(_ context.Context, _ Assignment, _ Manifest, hooks ExecutionHooks) (ExecutionResult, error) {
			if err := hooks.Start(); err != nil {
				return ExecutionResult{}, err
			}
			executions.Add(1)
			return ExecutionResult{Outcome: "succeeded"}, nil
		}}
	if err := transport.step(ctx); err == nil || !saved.Started || saved.Outcome != "unknown" {
		t.Fatalf("start uncertainty was not persisted: %v", err)
	}
	transport.journal = saved
	_ = transport.step(ctx)
	if starts.Load() != 1 || executions.Load() != 0 {
		t.Fatal("a lost start response caused a repeated launch")
	}
}
