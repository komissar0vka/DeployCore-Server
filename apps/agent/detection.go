package main

import "context"

type DetectionState string

const (
	installed    DetectionState = "installed"
	notInstalled DetectionState = "not_installed"
	unknown      DetectionState = "unknown"
)

type Detector func(context.Context, Detection) DetectionState

func observeLeaf(ctx context.Context, rule Detection, leaf Detector) DetectionState {
	if ctx.Err() != nil {
		return unknown
	}
	state := leaf(ctx, rule)
	if ctx.Err() != nil {
		return unknown
	}
	return state
}

func (rule Detection) validLeaf() bool {
	if len(rule.Rules) != 0 || rule.SchemaVersion != 0 {
		return false
	}
	switch rule.Kind {
	case "registry_software":
		return rule.DisplayName != "" && rule.Version != ""
	case "msi_product":
		return deviceIDPattern.MatchString(rule.ProductCode)
	case "file_exists":
		return rule.Path != ""
	case "file_version":
		return rule.Path != "" && rule.Version != ""
	default:
		return false
	}
}

func evaluateDetection(ctx context.Context, rule Detection, leaf Detector) DetectionState {
	if rule.validLeaf() {
		return observeLeaf(ctx, rule, leaf)
	}
	if (rule.Kind != "all" && rule.Kind != "any") || rule.SchemaVersion != 1 || len(rule.Rules) < 2 || len(rule.Rules) > 8 {
		return unknown
	}
	for _, child := range rule.Rules {
		if !child.validLeaf() {
			return unknown
		}
	}
	decisive, fallback := notInstalled, installed
	if rule.Kind == "any" {
		decisive, fallback = installed, notInstalled
	}
	for _, child := range rule.Rules {
		state := observeLeaf(ctx, child, leaf)
		if state == decisive {
			return decisive
		}
		if state == unknown {
			fallback = unknown
		}
	}
	return fallback
}

func desiredDetection(operation string) DetectionState {
	if operation == "install" {
		return installed
	}
	return notInstalled
}

func verificationResult(operation string, state DetectionState) (string, string) {
	switch {
	case state == unknown:
		return "unknown", "detection_failed"
	case state == desiredDetection(operation):
		return "succeeded", ""
	default:
		return "failed", "detection_mismatch"
	}
}
