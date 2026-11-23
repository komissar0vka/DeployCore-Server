package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type Assignment struct {
	TargetID  string `json:"target_id"`
	AttemptID string `json:"attempt_id"`
	VersionID string `json:"version_id"`
	Operation string `json:"operation"`
	Mode      string `json:"mode"`
}

func (a Assignment) valid() bool {
	return (a.Mode == "transport_only" || a.Mode == "execute_v1") && deviceIDPattern.MatchString(a.TargetID) &&
		deviceIDPattern.MatchString(a.AttemptID) && deviceIDPattern.MatchString(a.VersionID) &&
		(a.Operation == "install" || a.Operation == "uninstall")
}

type JobJournal struct {
	Server      string     `json:"server"`
	DeviceID    string     `json:"device_id"`
	Job         Assignment `json:"job"`
	Outcome     string     `json:"outcome,omitempty"`
	Started     bool       `json:"started,omitempty"`
	ExitCode    *uint32    `json:"exit_code,omitempty"`
	Diagnostic  string     `json:"diagnostic,omitempty"`
	OutputBytes *int64     `json:"output_bytes,omitempty"`
}

type JobTransport struct {
	client  *Client
	state   State
	journal JobJournal
	save    func(JobJournal) error
	log     *log.Logger
	execute Executor
}

func (t *JobTransport) persist(next JobJournal) error {
	if err := t.save(next); err != nil {
		return fmt.Errorf("save deployment journal: %w", err)
	}
	t.journal = next
	return nil
}

func (t *JobTransport) run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := t.step(ctx); err != nil && ctx.Err() == nil {
			var status StatusError
			if !errors.As(err, &status) || status != http.StatusNotFound {
				t.log.Printf("Deployment transport: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *JobTransport) step(ctx context.Context) error {
	base := "/api/v1/agent/" + t.state.DeviceID + "/jobs/"
	if t.journal.Job.AttemptID == "" {
		var poll struct {
			Assignment *Assignment `json:"assignment"`
		}
		if err := t.client.requestWithCapability(ctx, http.MethodPost, base+"poll", t.state.Credential, nil, &poll, t.execute != nil); err != nil {
			return err
		}
		if poll.Assignment == nil {
			return nil
		}
		if !poll.Assignment.valid() {
			return fmt.Errorf("unsupported deployment assignment")
		}
		if err := t.persist(JobJournal{Server: t.state.Server, DeviceID: t.state.DeviceID, Job: *poll.Assignment}); err != nil {
			return err
		}
		t.log.Printf("Deployment received: %s", poll.Assignment.TargetID)
	}

	next := t.journal
	if next.DeviceID != t.state.DeviceID || next.Server != t.state.Server || !next.Job.valid() ||
		(next.Job.Mode == "execute_v1" && t.execute == nil) {
		return fmt.Errorf("invalid deployment journal for this agent")
	}
	path := base + next.Job.TargetID + "/"
	lease := struct {
		AttemptID string `json:"attempt_id"`
	}{next.Job.AttemptID}

	if next.Outcome == "" {
		if err := t.client.request(ctx, http.MethodPost, path+"ack", t.state.Credential, lease, nil); err != nil {
			var status StatusError
			if errors.As(err, &status) && status == http.StatusConflict {
				// The server rejects only a closed, unknown, or expired unacknowledged delivery.
				return t.persist(JobJournal{})
			}
			return err
		}
		if next.Job.Mode == "execute_v1" {
			if err := t.executeJob(ctx, path); err != nil {
				return err
			}
			next = t.journal
		} else {
			var heartbeat struct {
				CancelRequested bool `json:"cancel_requested"`
			}
			if err := t.client.request(ctx, http.MethodPost, path+"heartbeat", t.state.Credential, lease, &heartbeat); err != nil {
				return err
			}
			next.Outcome = "not_executed"
			if heartbeat.CancelRequested {
				next.Outcome = "cancelled"
			}
			if err := t.persist(next); err != nil {
				return err
			}
		}
	}
	result := struct {
		AttemptID string `json:"attempt_id"`
		ExecutionResult
	}{next.Job.AttemptID, ExecutionResult{Outcome: next.Outcome, Diagnostic: next.Diagnostic,
		ExitCode: next.ExitCode, OutputBytes: next.OutputBytes}}
	if err := t.client.request(ctx, http.MethodPost, path+"result", t.state.Credential, result, nil); err != nil {
		return err
	}
	t.log.Printf("Deployment result accepted: %s %s", next.Job.TargetID, next.Outcome)
	return t.persist(JobJournal{})
}

func (t *JobTransport) executeJob(parent context.Context, path string) error {
	if t.journal.Started {
		return t.recordExecution(ExecutionResult{Outcome: "unknown", Diagnostic: "interrupted"})
	}
	attempt, job := t.journal.Job.AttemptID, t.journal.Job
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var cancellation atomic.Bool
	heartbeat := func(stage string) error {
		data := struct {
			AttemptID string `json:"attempt_id"`
			Stage     string `json:"stage,omitempty"`
		}{attempt, stage}
		var response struct {
			CancelRequested bool `json:"cancel_requested"`
		}
		err := t.client.request(ctx, http.MethodPost, path+"heartbeat", t.state.Credential, data, &response)
		if response.CancelRequested {
			cancellation.Store(true)
			cancel()
			return context.Canceled
		}
		var status StatusError
		if errors.As(err, &status) && (status == http.StatusUnauthorized || status == http.StatusConflict) {
			cancel()
		}
		return err
	}
	if err := heartbeat(""); err != nil {
		if cancellation.Load() {
			return t.recordExecution(ExecutionResult{Outcome: "cancelled"})
		}
		return err
	}
	suffix := "?attempt_id=" + attempt
	var manifest Manifest
	if err := t.client.request(ctx, http.MethodGet, path+"manifest"+suffix, t.state.Credential, nil, &manifest); err != nil {
		var status StatusError
		if errors.As(err, &status) && status == http.StatusConflict {
			return t.recordExecution(ExecutionResult{Outcome: "failed", Diagnostic: "manifest_invalid"})
		}
		return err
	}
	if !manifest.valid() {
		return t.recordExecution(ExecutionResult{Outcome: "failed", Diagnostic: "manifest_invalid"})
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = heartbeat("")
			}
		}
	}()
	result, err := t.execute(ctx, job, manifest, ExecutionHooks{
		Stage: heartbeat,
		Download: func(destination string, m Manifest) error {
			return t.client.download(ctx, path+"artifact"+suffix, t.state.Credential, destination, m)
		},
		Start: func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			next := t.journal
			next.Started = true
			if err := t.persist(next); err != nil {
				return err
			}
			payload := struct {
				AttemptID string `json:"attempt_id"`
			}{attempt}
			return t.client.request(ctx, http.MethodPost, path+"start", t.state.Credential, payload, nil)
		},
	})
	cancel()
	<-stopped
	if err != nil {
		if t.journal.Started {
			return t.recordExecution(ExecutionResult{Outcome: "unknown", Diagnostic: "interrupted"})
		}
		if cancellation.Load() {
			return t.recordExecution(ExecutionResult{Outcome: "cancelled"})
		}
		return err
	}
	return t.recordExecution(result)
}

func (t *JobTransport) recordExecution(result ExecutionResult) error {
	next := t.journal
	next.Outcome, next.ExitCode, next.Diagnostic, next.OutputBytes = result.Outcome, result.ExitCode, result.Diagnostic, result.OutputBytes
	return t.persist(next)
}
