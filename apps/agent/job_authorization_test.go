package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExecutionAuthorizationAndLocalPolicy(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const id = "execution-test"
	encode := base64.RawURLEncoding.EncodeToString
	raw, err := json.Marshal(Manifest{Installer: "exe", Architecture: "x64", Size: 10, Hash: strings.Repeat("a", 64),
		TimeoutSeconds: 10, SuccessCodes: []uint32{0}, Args: []string{"/quiet"}})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	trust := JobTrust{Keys: map[string]string{id: encode(pub)},
		ManifestOperations: map[string][]string{hex.EncodeToString(hash[:]): {"install"}}}
	if err := trust.validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	job := Assignment{TargetID: "00000000-0000-0000-0000-000000000001", AttemptID: "00000000-0000-0000-0000-000000000002",
		VersionID: "00000000-0000-0000-0000-000000000003", Operation: "install", Mode: "execute_v1"}
	const device = "00000000-0000-0000-0000-000000000004"
	authorization := executionAuthorization{DeviceID: device, TargetID: job.TargetID, AttemptID: job.AttemptID,
		VersionID: job.VersionID, Operation: job.Operation, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Manifest: raw}
	sign := func(a executionAuthorization) signedExecution {
		payload, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		signed := ed25519.Sign(private, append([]byte(executionContext+id+"\x00"), payload...))
		return signedExecution{Version: 1, KeyID: id, Payload: encode(payload), Signature: encode(signed)}
	}
	envelope := sign(authorization)
	if _, expires, err := trust.verify(envelope, device, job, now); err != nil || !expires.Equal(authorization.ExpiresAt) {
		t.Fatalf("valid authorization rejected: %v", err)
	}
	if _, _, err := trust.verify(envelope, "other-device", job, now); err == nil {
		t.Fatal("authorization for another device accepted")
	}
	if _, _, err := trust.verify(envelope, device, job, now.Add(time.Minute)); err == nil {
		t.Fatal("expired authorization accepted")
	}
	authorization.Manifest = json.RawMessage(strings.Replace(string(raw), "/quiet", "/other", 1))
	if _, _, err := trust.verify(sign(authorization), device, job, now); err == nil {
		t.Fatal("different manifest signed by trusted server bypassed local policy")
	}
	envelope.Payload = encode([]byte("{}"))
	if _, _, err := trust.verify(envelope, device, job, now); err == nil {
		t.Fatal("modified payload accepted")
	}
}

func TestExecutionReplaySurvivesSerialization(t *testing.T) {
	now := time.Now().UTC()
	next, err := (jobReplay{}).consume("target", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	var restored jobReplay
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.consume("target", now.Add(2*time.Minute), now.Add(time.Minute)); err == nil {
		t.Fatal("new authorization for previously consumed target accepted")
	}
	if _, err := restored.consume("another", now, now); err == nil {
		t.Fatal("expired authorization accepted at start")
	}
}

func TestStrictExecutionJSON(t *testing.T) {
	for _, malformed := range []string{
		`{"device_id":"one","device_id":"two"}`,
		`{"manifest":{"args":[],"args":["other"]}}`,
		`{"keys":{"test":"one","\u0074est":"two"}}`,
		`{}{}`,
	} {
		if uniqueJSONKeys([]byte(malformed)) {
			t.Errorf("ambiguous JSON accepted: %s", malformed)
		}
	}
	if !uniqueJSONKeys([]byte(`{"a":[{"key":1},{"key":2}],"b":null}`)) {
		t.Error("valid nested JSON rejected")
	}
}
