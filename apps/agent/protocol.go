package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

//go:embed VERSION
var release string

var version = strings.TrimSpace(release)
var deviceIDPattern = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)

type State struct {
	Server       string `json:"server"`
	CA           []byte `json:"ca,omitempty"`
	DeviceID     string `json:"device_id"`
	Credential   string `json:"credential"`
	PendingToken string `json:"pending_token,omitempty"`
}

type Heartbeat struct {
	Hostname     string   `json:"hostname"`
	FQDN         string   `json:"fqdn"`
	NetworkName  string   `json:"network_name"`
	DomainJoined bool     `json:"domain_joined"`
	IPs          []string `json:"ips"`
	OSVersion    string   `json:"os_version"`
	AgentVersion string   `json:"agent_version"`
	Uptime       uint64   `json:"uptime_seconds"`
}

type Enrollment struct {
	InstallationID  string    `json:"installation_id"`
	EnrollmentToken string    `json:"enrollment_token"`
	Credential      string    `json:"credential"`
	Heartbeat       Heartbeat `json:"heartbeat"`
}

type Connection struct {
	DeviceID         string    `json:"device_id"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	LastSeenAt       time.Time `json:"last_seen_at"`
}

type Inventory struct {
	Hardware Hardware   `json:"hardware"`
	Software []Software `json:"software"`
}

type Hardware struct {
	Manufacturer string             `json:"manufacturer,omitempty"`
	Model        string             `json:"model,omitempty"`
	OS           OSInfo             `json:"os"`
	CPUs         []CPU              `json:"cpus"`
	RAM          uint64             `json:"ram_bytes"`
	Disks        []Disk             `json:"disks"`
	Interfaces   []NetworkInterface `json:"interfaces"`
}

type OSInfo struct {
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
}

type CPU struct {
	Model   string `json:"model"`
	Cores   int    `json:"cores"`
	Threads int    `json:"threads"`
}

type Disk struct {
	Filesystem string `json:"filesystem,omitempty"`
	Label      string `json:"label,omitempty"`
	Letter     string `json:"letter"`
	Size       uint64 `json:"size_bytes"`
	Free       uint64 `json:"free_bytes"`
}

type NetworkInterface struct {
	MAC  string   `json:"mac,omitempty"`
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
}

type StatusError int

func (s StatusError) Error() string { return fmt.Sprintf("DeployCore responded HTTP %d", s) }

type Client struct {
	origin string
	http   *http.Client
}

func secureOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("server must be an HTTPS origin")
	}
	return "https://" + u.Host, nil
}

func newClient(origin string, ca []byte) (*Client, error) {
	origin, err := secureOrigin(origin)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(ca) != 0 {
		tlsConfig.RootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load OS trust roots: %w", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA file does not contain a PEM certificate")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	return &Client{
		origin: origin,
		http: &http.Client{
			Timeout:       15 * time.Second,
			Transport:     transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) request(ctx context.Context, method, path, credential string, in, out any) error {
	return c.requestWithCapability(ctx, method, path, credential, in, out, "")
}

func (c *Client) requestWithCapability(ctx context.Context, method, path, credential string, in, out any, capabilities string) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return err
		}
		if len(encoded) > 2*1024*1024 {
			return fmt.Errorf("inventory exceeds request size limit")
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	if capabilities != "" {
		req.Header.Set("X-DeployCore-Capabilities", capabilities)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return StatusError(res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(out)
	}
	return nil
}

func (c *Client) checkReady(ctx context.Context) error {
	var response struct {
		Status string `json:"status"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/health/ready", "", nil, &response); err != nil {
		return fmt.Errorf("DeployCore HTTPS readiness check: %w", err)
	}
	if response.Status != "ok" {
		return fmt.Errorf("server did not report DeployCore readiness")
	}
	return nil
}

func (c *Client) beat(ctx context.Context, state State, beat Heartbeat) (Connection, error) {
	var reply Connection
	path := "/api/v1/agent/" + state.DeviceID + "/heartbeat"
	err := c.request(ctx, http.MethodPost, path, state.Credential, beat, &reply)
	if err == nil && reply.DeviceID != state.DeviceID {
		err = fmt.Errorf("unexpected device ID in heartbeat response")
	}
	return reply, err
}

func validToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 43
}

func randomCredential() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func installationID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	data[6] = data[6]&0x0f | 0x40
	data[8] = data[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:]), nil
}

func clean(value string, maxLen int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	runes := []rune(value)
	return string(runes[:min(len(runes), maxLen)])
}
