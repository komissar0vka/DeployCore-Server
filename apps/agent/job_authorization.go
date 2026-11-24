package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const executionContext = "DeployCore-execution-v1\x00"
const maxAuthorizationLifetime = 15 * time.Minute
const maxReplayEntries = 4096

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)

type JobTrust struct {
	Keys map[string]string `json:"keys"`
	// The ID of each entry is an independently approved SHA-256 of the exact signed manifest.
	ManifestOperations map[string][]string `json:"manifest_operations"`
}

type signedExecution struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type executionAuthorization struct {
	DeviceID  string          `json:"device_id"`
	TargetID  string          `json:"target_id"`
	AttemptID string          `json:"attempt_id"`
	VersionID string          `json:"version_id"`
	Operation string          `json:"operation"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Manifest  json.RawMessage `json:"manifest"`
}

func (p JobTrust) validate() error {
	if len(p.Keys) == 0 || len(p.ManifestOperations) == 0 {
		return errors.New("job trust requires signing keys and approved manifests")
	}
	for id, encoded := range p.Keys {
		key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if !keyIDPattern.MatchString(id) || err != nil || len(key) != ed25519.PublicKeySize {
			return errors.New("invalid job trust key")
		}
	}
	for hash, operations := range p.ManifestOperations {
		if !hexDigest.MatchString(hash) || len(operations) == 0 {
			return errors.New("invalid approved manifest")
		}
		for _, operation := range operations {
			if operation != "install" && operation != "uninstall" {
				return errors.New("invalid approved operation")
			}
		}
	}
	return nil
}

func (p JobTrust) verify(s signedExecution, device string, job Assignment, now time.Time) (Manifest, time.Time, error) {
	var manifest Manifest
	decode := base64.RawURLEncoding.Strict().DecodeString
	key, err := decode(p.Keys[s.KeyID])
	if s.Version != 1 || !keyIDPattern.MatchString(s.KeyID) || err != nil || len(key) != ed25519.PublicKeySize {
		return manifest, time.Time{}, errors.New("unknown job signer")
	}
	payload, err := decode(s.Payload)
	if err != nil || len(payload) == 0 || len(payload) > 40*1024 {
		return manifest, time.Time{}, errors.New("invalid signed job payload")
	}
	signature, err := decode(s.Signature)
	message := append([]byte(executionContext+s.KeyID+"\x00"), payload...)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
		return manifest, time.Time{}, errors.New("invalid job signature")
	}
	var a executionAuthorization
	if err := json.Unmarshal(payload, &a); err != nil ||
		a.DeviceID != device || a.TargetID != job.TargetID || a.AttemptID != job.AttemptID ||
		a.VersionID != job.VersionID || a.Operation != job.Operation {
		return manifest, time.Time{}, errors.New("signed job does not match assignment")
	}
	if a.IssuedAt.After(now.Add(30*time.Second)) || !a.ExpiresAt.After(now) ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.Sub(a.IssuedAt) > maxAuthorizationLifetime {
		return manifest, time.Time{}, errors.New("signed job expired or invalid lifetime")
	}
	hash := sha256.Sum256(a.Manifest)
	for _, operation := range p.ManifestOperations[hex.EncodeToString(hash[:])] {
		if operation == a.Operation {
			if err := json.Unmarshal(a.Manifest, &manifest); err != nil || !manifest.valid() {
				return Manifest{}, time.Time{}, errors.New("signed manifest is invalid")
			}
			return manifest, a.ExpiresAt, nil
		}
	}
	return manifest, time.Time{}, errors.New("signed job is outside local trust policy")
}

type jobReplay map[string]time.Time

func (r jobReplay) consume(target string, expires, now time.Time) (jobReplay, error) {
	if !expires.After(now) {
		return nil, errors.New("job authorization expired before start")
	}
	next := make(jobReplay, len(r)+1)
	for id, expiry := range r {
		if expiry.After(now) {
			next[id] = expiry
		}
	}
	if next[target].After(now) {
		return nil, fmt.Errorf("job target already executed: %s", target)
	}
	if len(next) >= maxReplayEntries {
		return nil, errors.New("job replay store exhausted")
	}
	next[target] = now.Add(24 * time.Hour)
	return next, nil
}
