// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"net"
	"os"
	"testing"

	"github.com/prodrom3/triton/internal/models"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{"80,443", []int{80, 443}, false},
		{"22", []int{22}, false},
		{"80, 443, 8080", []int{80, 443, 8080}, false},
		{"", nil, false},
		{"abc", nil, true},
		{"0", nil, true},
		{"65536", nil, true},
		{"-1", nil, true},
		{"80,99999", nil, true},
	}

	for _, tc := range tests {
		ports, err := parsePorts(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("parsePorts(%q): expected error", tc.input)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("parsePorts(%q): unexpected error: %v", tc.input, err)
		}
		if !tc.wantErr && len(ports) != len(tc.want) {
			t.Errorf("parsePorts(%q): got %v, want %v", tc.input, ports, tc.want)
		}
	}
}

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		input []string
		want  int
	}{
		{[]string{"a", "b", "c"}, 3},
		{[]string{"a", "a", "b"}, 2},
		{[]string{"x", "x", "x"}, 1},
		{nil, 0},
		{[]string{}, 0},
	}

	for _, tc := range tests {
		got := deduplicate(tc.input)
		if len(got) != tc.want {
			t.Errorf("deduplicate(%v): got %d unique, want %d", tc.input, len(got), tc.want)
		}
	}
}

func TestDeduplicatePreservesOrder(t *testing.T) {
	input := []string{"c", "a", "b", "a", "c"}
	got := deduplicate(input)
	if len(got) != 3 || got[0] != "c" || got[1] != "a" || got[2] != "b" {
		t.Errorf("deduplicate should preserve first-seen order, got %v", got)
	}
}

func TestIncIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.0.0.1", "10.0.0.2"},
		{"10.0.0.255", "10.0.1.0"},
		{"10.0.255.255", "10.1.0.0"},
		{"0.0.0.0", "0.0.0.1"},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.input).To4()
		incIP(ip)
		got := ip.String()
		if got != tc.want {
			t.Errorf("incIP(%s) = %s, want %s", tc.input, got, tc.want)
		}
	}
}

func TestExpandCIDR_Single(t *testing.T) {
	// /32 should produce bare IP, not CIDR string
	got := expandCIDR([]string{"10.0.0.1/32"})
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0] == "10.0.0.1/32" {
		t.Error("/32 should be expanded to bare IP, not CIDR notation")
	}
	if got[0] != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got[0])
	}
}

func TestExpandCIDR_Subnet(t *testing.T) {
	got := expandCIDR([]string{"10.0.0.0/30"})
	// /30 = 4 addresses, minus network (.0) and broadcast (.3) = 2 hosts
	if len(got) != 2 {
		t.Errorf("expected 2 hosts for /30, got %d: %v", len(got), got)
	}
	for _, ip := range got {
		if ip == "10.0.0.0" || ip == "10.0.0.3" {
			t.Errorf("should not include network/broadcast address: %s", ip)
		}
	}
}

func TestExpandCIDR_SubnetSmall(t *testing.T) {
	// /28 = 16 addresses, 14 usable hosts
	got := expandCIDR([]string{"10.0.0.16/28"})
	if len(got) != 14 {
		t.Errorf("expected 14 hosts for /28, got %d", len(got))
	}
	for _, ip := range got {
		if ip == "10.0.0.16" {
			t.Error("should not include network address 10.0.0.16")
		}
		if ip == "10.0.0.31" {
			t.Error("should not include broadcast address 10.0.0.31")
		}
	}
}

func TestExpandCIDR_NonCIDR(t *testing.T) {
	got := expandCIDR([]string{"example.com", "8.8.8.8"})
	if len(got) != 2 || got[0] != "example.com" || got[1] != "8.8.8.8" {
		t.Errorf("non-CIDR targets should pass through unchanged, got %v", got)
	}
}

func TestExpandCIDR_TooLarge(t *testing.T) {
	got := expandCIDR([]string{"10.0.0.0/8"})
	if len(got) != 0 {
		t.Errorf("expected /8 to be skipped (too large), got %d results", len(got))
	}
}

func TestApplyConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.triton.json"
	cfgJSON := `{"workers":8,"ping_port":8080,"retries":3,"ports":"22,3389","no_traceroute":true}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &cliConfig{
		configFile: path,
		workers:    4,  // flag default
		pingPort:   80, // flag default
		retries:    0,  // flag default
		maxHops:    20,
		timeout:    30.0,
	}
	// Simulate: user explicitly passed --workers and --ping-port (even though
	// --ping-port 80 equals the default), but not --retries or --ports.
	setFlags := map[string]bool{"workers": true, "ping-port": true}

	if err := applyConfigFile(cfg, setFlags); err != nil {
		t.Fatal(err)
	}

	if cfg.workers != 4 {
		t.Errorf("explicit --workers must win over config: got %d want 4", cfg.workers)
	}
	if cfg.pingPort != 80 {
		t.Errorf("explicit --ping-port 80 must win over config: got %d want 80", cfg.pingPort)
	}
	if cfg.retries != 3 {
		t.Errorf("unset --retries must take config value: got %d want 3", cfg.retries)
	}
	if cfg.ports != "22,3389" || !cfg.doPorts {
		t.Errorf("config ports must apply: ports=%q doPorts=%v", cfg.ports, cfg.doPorts)
	}
	if !cfg.noTraceroute {
		t.Errorf("config no_traceroute must apply when flag unset")
	}
}

func TestParseFailOn(t *testing.T) {
	got, err := parseFailOn("cert-expiry, open-ports ,changed")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"cert-expiry", "open-ports", "changed"} {
		if !got[c] {
			t.Errorf("condition %q missing from parsed set", c)
		}
	}
	if _, err := parseFailOn("nonsense"); err == nil {
		t.Error("expected error for unknown condition")
	}
	if s, err := parseFailOn(""); err != nil || len(s) != 0 {
		t.Errorf("empty fail-on should be empty set: %v %v", s, err)
	}
}

func TestFailOnTriggered(t *testing.T) {
	expired := models.AnalysisResult{
		Target: "a", TLS: &models.TlsCertResult{Success: true, Expired: true},
	}
	weak := models.AnalysisResult{
		Target: "b", TLS: &models.TlsCertResult{Success: true, Grade: "F",
			WeakProtocols: []string{"TLSv1.0"}},
	}
	openPorts := models.AnalysisResult{
		Target: "c", Ports: []models.PortResult{{Port: 80, Open: true}},
	}
	clean := models.AnalysisResult{
		Target: "d", IsIP: true, TLS: &models.TlsCertResult{Success: true, Grade: "A"},
	}

	tests := []struct {
		name    string
		conds   string
		results []models.AnalysisResult
		changed bool
		want    bool
	}{
		{"cert-expiry hit", "cert-expiry", []models.AnalysisResult{expired}, false, true},
		{"weak-tls hit", "weak-tls", []models.AnalysisResult{weak}, false, true},
		{"open-ports hit", "open-ports", []models.AnalysisResult{openPorts}, false, true},
		{"changed hit", "changed", []models.AnalysisResult{clean}, true, true},
		{"no match", "cert-expiry,weak-tls,open-ports", []models.AnalysisResult{clean}, false, false},
		{"changed but not requested", "open-ports", []models.AnalysisResult{clean}, true, false},
	}
	for _, tc := range tests {
		conds, _ := parseFailOn(tc.conds)
		got, _ := failOnTriggered(conds, tc.results, 30, tc.changed)
		if got != tc.want {
			t.Errorf("%s: failOnTriggered = %v want %v", tc.name, got, tc.want)
		}
	}
}
