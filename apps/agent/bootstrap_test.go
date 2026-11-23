package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMSIBootstrap(t *testing.T) {
	token, err := randomCredential()
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		server string
		token  string
		valid  bool
	}{
		{"https://192.0.2.14:8444/", token, true},
		{"http://192.0.2.14:8444", token, false},
		{"https://192.0.2.14:8444/settings", token, false},
		{"https://192.0.2.14:8444", "invalid", false},
	} {
		data, _ := json.Marshal(enrollmentBootstrap{Server: example.server, Token: example.token})
		config, err := parseBootstrap(strings.NewReader(string(data)))
		if (err == nil) != example.valid {
			t.Fatalf("unexpected validation for %q: %v", example.server, err)
		}
		if example.valid && (config.Server != "https://192.0.2.14:8444" || config.Token != token) {
			t.Fatal("bootstrap did not preserve the HTTPS origin and token")
		}
	}
	if _, err := parseBootstrap(strings.NewReader(strings.Repeat("x", maxBootstrapBytes+1))); err == nil {
		t.Fatal("oversized configuration was accepted")
	}
}
