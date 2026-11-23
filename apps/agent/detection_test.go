package main

import (
	"context"
	"testing"
)

func TestDetectionGroupThreeValuedLogic(t *testing.T) {
	for _, test := range []struct {
		kind                  string
		left, right, expected DetectionState
	}{
		{"all", unknown, notInstalled, notInstalled},
		{"all", installed, unknown, unknown},
		{"all", installed, installed, installed},
		{"any", unknown, installed, installed},
		{"any", notInstalled, unknown, unknown},
		{"any", notInstalled, notInstalled, notInstalled},
	} {
		rule := Detection{Kind: test.kind, SchemaVersion: 1, Rules: []Detection{
			{Kind: "file_exists", Path: string(test.left)},
			{Kind: "file_exists", Path: string(test.right)},
		}}
		leaf := func(_ context.Context, rule Detection) DetectionState { return DetectionState(rule.Path) }
		if got := evaluateDetection(context.Background(), rule, leaf); got != test.expected {
			t.Errorf("%s(%s, %s) = %s; want %s", test.kind, test.left, test.right, got, test.expected)
		}
	}
}

func TestVerificationDistinguishesUnavailableAndMismatch(t *testing.T) {
	if outcome, diag := verificationResult("install", unknown); outcome != "unknown" || diag != "detection_failed" {
		t.Fatalf("unavailable detection: %s/%s", outcome, diag)
	}
	if outcome, diag := verificationResult("install", notInstalled); outcome != "failed" || diag != "detection_mismatch" {
		t.Fatalf("known mismatch: %s/%s", outcome, diag)
	}
	if outcome, diag := verificationResult("uninstall", notInstalled); outcome != "succeeded" || diag != "" {
		t.Fatalf("verified removal: %s/%s", outcome, diag)
	}
}
