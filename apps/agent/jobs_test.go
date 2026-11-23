package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJobTransportResumesDurableResult(t *testing.T) {
	ctx := context.Background()
	state := testState(t, "https://deploycore.example")
	assignment := Assignment{
		TargetID: "11111111-1111-4111-8111-111111111111", AttemptID: "22222222-2222-4222-8222-222222222222",
		VersionID: "33333333-3333-4333-8333-333333333333", Operation: "install", Mode: "transport_only",
	}
	var journal JobJournal
	var lock sync.Mutex
	calls := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+state.Credential || r.Method != http.MethodPost {
			t.Error("unexpected credentials or method")
		}
		action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		calls[action]++
		switch action {
		case "poll":
			_ = json.NewEncoder(w).Encode(map[string]Assignment{"assignment": assignment})
		case "ack":
			if journal.Job.AttemptID != assignment.AttemptID {
				t.Error("attempt was acknowledged before persistence")
			}
			if calls[action] == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		case "heartbeat":
			_, _ = w.Write([]byte(`{"cancel_requested":true}`))
		case "result":
			var payload struct {
				AttemptID string `json:"attempt_id"`
				Outcome   string `json:"outcome"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.AttemptID != assignment.AttemptID ||
				payload.Outcome != "cancelled" || journal.Outcome != payload.Outcome {
				t.Error("unexpected or unpersisted terminal result")
			}
			if calls[action] == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			t.Error("unexpected path")
		}
	}))
	defer server.Close()
	client := trustedClient(t, server)
	snapshot := func() JobJournal {
		lock.Lock()
		defer lock.Unlock()
		return journal
	}
	transport := func() *JobTransport {
		return &JobTransport{client: client, state: state, journal: snapshot(), log: log.New(io.Discard, "", 0),
			save: func(next JobJournal) error {
				lock.Lock()
				defer lock.Unlock()
				journal = next
				return nil
			}}
	}
	if err := transport().step(ctx); err == nil || snapshot().Job.AttemptID == "" || snapshot().Outcome != "" {
		t.Fatal("failed ACK did not retain the delivery")
	}
	if err := transport().step(ctx); err == nil || snapshot().Outcome != "cancelled" {
		t.Fatal("failed result did not retain the terminal outcome")
	}
	if err := transport().step(ctx); err != nil || snapshot() != (JobJournal{}) {
		t.Fatalf("replay failed or retained the journal: %v", err)
	}
	lock.Lock()
	defer lock.Unlock()
	if calls["poll"] != 1 || calls["ack"] != 2 || calls["heartbeat"] != 1 || calls["result"] != 2 {
		t.Fatalf("unexpected protocol calls: %v", calls)
	}
}

func TestRebootVerificationResumesWithoutExecution(t *testing.T) {
	state := testState(t, "https://deploycore.example")
	job := Assignment{
		TargetID: "11111111-1111-4111-8111-111111111111", AttemptID: "22222222-2222-4222-8222-222222222222",
		VersionID: "33333333-3333-4333-8333-333333333333", Mode: "execute_v1", Operation: "install",
	}
	var initial, rechecks atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]; action {
		case "result":
			var result ExecutionResult
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil || !result.RebootPending || result.Outcome != "reboot_required" {
				t.Error("pending reboot was not reported")
			}
			initial.Add(1)
		case "reboot-result":
			var result struct {
				Detection DetectionState
			}
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil || result.Detection != installed {
				t.Error("unexpected recheck observation")
			}
			if rechecks.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			t.Errorf("unexpected %s request", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := trustedClient(t, server)
	boot, checks := "original", 0
	exit := uint32(3010)
	journal := JobJournal{Server: state.Server, DeviceID: state.DeviceID, Job: job, Started: true, Outcome: "reboot_required",
		ExitCode: &exit, Detection: notInstalled, Reboot: &RebootCheck{
			Rule: Detection{Kind: "file_exists", Path: `C:\marker.exe`}, Boot: boot, Deadline: time.Now().Add(time.Hour),
		}}
	step := func() error {
		transport := JobTransport{client: client, state: state, journal: journal, log: log.New(io.Discard, "", 0),
			save: func(next JobJournal) error { journal = next; return nil },
			execute: func(context.Context, Assignment, Manifest, ExecutionHooks) (ExecutionResult, error) {
				t.Error("restarted installer")
				return ExecutionResult{}, nil
			},
			detect: func(_ context.Context, rule Detection) DetectionState {
				checks++
				if rule.Path != `C:\marker.exe` {
					t.Error("verification did not use the journaled rule")
				}
				return installed
			}, bootID: func() string { return boot },
		}
		return transport.step(context.Background())
	}
	if err := step(); err != nil || checks != 0 || journal.Reboot == nil || !journal.Reboot.Reported {
		t.Fatalf("same boot did not retain pending check: %v", err)
	}
	if err := step(); err != nil || checks != 0 {
		t.Fatalf("service restart triggered a recheck: %v", err)
	}
	boot = "after-restart"
	if err := step(); err == nil || checks != 1 || journal.Reboot.Observation == nil {
		t.Fatalf("failed transmission did not retain recheck: %v", err)
	}
	if err := step(); err != nil || checks != 1 || journal != (JobJournal{}) {
		t.Fatalf("verification was not replayed and cleared: %v", err)
	}
	if initial.Load() != 1 || rechecks.Load() != 2 {
		t.Fatal("unexpected number of reports")
	}
}
