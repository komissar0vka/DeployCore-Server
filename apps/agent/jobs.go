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

type RebootCheck struct {
	Rule        Detection       `json:"rule"`
	Boot        string          `json:"boot"`
	Reported    bool            `json:"reported,omitempty"`
	Deadline    time.Time       `json:"deadline"`
	Observation *DetectionState `json:"observation,omitempty"`
}

type JobJournal struct {
	ProcessStarted *bool          `json:"process_started,omitempty"`
	Detection      DetectionState `json:"detection,omitempty"`
	Reboot         *RebootCheck   `json:"reboot,omitempty"`

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
	detect  Detector
	bootID  func() string
}

func (t *JobTransport) capabilities() string {
	if t.detect != nil {
		return "execute_v1, detection_v1, closed_result_v1, portable_v1"
	}
	if t.execute != nil {
		return "execute_v1"
	}
	return ""
}

func (t *JobTransport) request(ctx context.Context, method, path string, in, out any) error {
	return t.client.requestWithCapability(ctx, method, path, t.state.Credential, in, out, t.capabilities())
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
		if err := t.request(ctx, http.MethodPost, base+"poll", nil, &poll); err != nil {
			return err
		}
		if poll.Assignment == nil {
			return t.preview(ctx)
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
	if next.Reboot != nil && next.Reboot.Reported {
		return t.recheck(ctx, path)
	}
	result := struct {
		AttemptID string `json:"attempt_id"`
		ExecutionResult
	}{next.Job.AttemptID, ExecutionResult{Outcome: next.Outcome, Diagnostic: next.Diagnostic,
		ExitCode: next.ExitCode, OutputBytes: next.OutputBytes, Detection: next.Detection, ProcessStarted: next.ProcessStarted, RebootPending: next.Reboot != nil}}
	if err := t.request(ctx, http.MethodPost, path+"result", result, nil); err != nil {
		return t.handleClosedAttempt(err)
	}
	if next.Reboot != nil {
		pending := *next.Reboot
		pending.Reported = true
		next.Reboot = &pending
		if err := t.persist(next); err != nil {
			return err
		}
		return t.recheck(ctx, path)
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
	if err := t.request(ctx, http.MethodGet, path+"manifest"+suffix, nil, &manifest); err != nil {
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
	boot := ""
	if t.bootID != nil {
		boot = t.bootID()
	}
	result, err := t.execute(ctx, job, manifest, ExecutionHooks{
		Stage: heartbeat,
		Download: func(destination string, m Manifest) error {
			return t.client.download(ctx, path+"artifact"+suffix, t.state.Credential, destination, m, t.capabilities())
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
			return t.request(ctx, http.MethodPost, path+"start", payload, nil)
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
	if result.RebootPending {
		next := t.journal
		next.Reboot = &RebootCheck{Rule: manifest.Detection, Boot: boot, Deadline: time.Now().Add(24 * time.Hour)}
		return t.persist(next.withResult(result))
	}
	return t.recordExecution(result)
}

func (t *JobTransport) recordExecution(result ExecutionResult) error {
	return t.persist(t.journal.withResult(result))
}

func (j JobJournal) withResult(result ExecutionResult) JobJournal {
	j.Outcome, j.ExitCode, j.Diagnostic, j.OutputBytes = result.Outcome, result.ExitCode, result.Diagnostic, result.OutputBytes
	j.Detection, j.ProcessStarted = result.Detection, result.ProcessStarted
	return j
}

func (t *JobTransport) recheck(ctx context.Context, path string) error {
	next := t.journal
	pending := *next.Reboot
	if pending.Observation == nil && time.Now().Before(pending.Deadline) {
		if t.detect == nil || t.bootID == nil || pending.Boot == "" {
			return nil
		}
		boot := t.bootID()
		if boot == "" || boot == pending.Boot {
			return nil
		}
		check, cancel := context.WithTimeout(ctx, 20*time.Second)
		observation := t.detect(check, pending.Rule)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pending.Observation = &observation
		next.Reboot = &pending
		if err := t.persist(next); err != nil {
			return err
		}
	}
	result := struct {
		AttemptID string          `json:"attempt_id"`
		Detection *DetectionState `json:"detection"`
	}{next.Job.AttemptID, pending.Observation}
	if err := t.request(ctx, http.MethodPost, path+"reboot-result", result, nil); err != nil {
		return t.handleClosedAttempt(err)
	}
	return t.persist(JobJournal{})
}

func (t *JobTransport) handleClosedAttempt(err error) error {
	var status StatusError
	if !errors.As(err, &status) || status != http.StatusGone {
		return err
	}
	t.log.Printf("Deployment attempt closed before the result was accepted: %s", t.journal.Job.AttemptID)
	return t.persist(JobJournal{})
}

func (t *JobTransport) preview(ctx context.Context) error {
	if t.detect == nil {
		return nil
	}
	base := "/api/v1/agent/" + t.state.DeviceID + "/detection-previews/"
	var poll struct {
		Task *struct {
			ID   string    `json:"id"`
			Rule Detection `json:"rule"`
		} `json:"task"`
	}
	if err := t.request(ctx, http.MethodPost, base+"poll", nil, &poll); err != nil || poll.Task == nil {
		return err
	}
	if !deviceIDPattern.MatchString(poll.Task.ID) {
		return fmt.Errorf("invalid detection preview ID")
	}
	check, cancel := context.WithTimeout(ctx, 20*time.Second)
	observation := t.detect(check, poll.Task.Rule)
	cancel()
	return t.request(ctx, http.MethodPost, base+poll.Task.ID+"/result", struct {
		Observation DetectionState `json:"observation"`
	}{observation}, nil)
}
