package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobTrustCannotSilentlyDowngradeAfterPolicyRemoval(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "job-trust.json")
	trust, _, err := loadJobTrust(directory)
	if err != nil || trust != nil {
		t.Fatalf("legacy policy initialization failed: %v", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := JobTrust{
		Keys:               map[string]string{"test": base64.RawURLEncoding.EncodeToString(public)},
		ManifestOperations: map[string][]string{strings.Repeat("a", 64): {"install"}},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	trust, replay, err := loadJobTrust(directory)
	if err != nil || trust == nil || replay == nil {
		t.Fatalf("strict policy initialization failed: %v", err)
	}
	now := time.Now()
	replay, err = replay.consume("00000000-0000-0000-0000-000000000001", now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveProtectedJSON(filepath.Join(directory, "job-replay.dpapi"), replay); err != nil {
		t.Fatal(err)
	}
	_, restored, err := loadJobTrust(directory)
	if err != nil || len(restored) != 1 {
		t.Fatalf("replay restoration failed: %v", err)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadJobTrust(directory); err == nil {
		t.Fatal("an enabled strict profile fell back to unsigned execution")
	}
}
