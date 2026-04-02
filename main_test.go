// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"net"
	"testing"
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
