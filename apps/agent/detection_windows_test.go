package main

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestRegistryDetectionDistinguishesMissingValuesAndReadErrors(t *testing.T) {
	path := fmt.Sprintf(`Software\DeployCore-DetectionTest-%d`, time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	defer key.Close()

	rule := Detection{Kind: "registry_software", DisplayName: "Fixture", Version: "1.2"}
	if got := detectRegistryEntry(key, rule); got != notInstalled {
		t.Fatalf("expected absence when DisplayName is missing, got %s", got)
	}
	if err := key.SetDWordValue("DisplayName", 1); err != nil {
		t.Fatal(err)
	}
	if got := detectRegistryEntry(key, rule); got != unknown {
		t.Fatalf("invalid DisplayName must be unknown, got %s", got)
	}
	if err := key.SetStringValue("DisplayName", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := key.SetDWordValue("DisplayVersion", 1); err != nil {
		t.Fatal(err)
	}
	if got := detectRegistryEntry(key, rule); got != unknown {
		t.Fatalf("invalid DisplayVersion must be unknown, got %s", got)
	}
	if err := key.SetStringValue("DisplayVersion", "1.2"); err != nil {
		t.Fatal(err)
	}
	if got := detectRegistryEntry(key, rule); got != installed {
		t.Fatalf("expected match, got %s", got)
	}
	writeOnly, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer writeOnly.Close()
	if got := detectRegistryEntry(writeOnly, rule); got != unknown {
		t.Fatalf("access denied must be unknown, got %s", got)
	}
}
