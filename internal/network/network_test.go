// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"testing"
	"time"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"999.999.999.999", false},
		{"not-an-ip", false},
		{"", false},
		{"192.168.1", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := ValidateIP(tc.input); got != tc.want {
				t.Errorf("ValidateIP(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeWhoisQuery(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"8.8.8.8", "8.8.8.8"},
		{"8.8.8.8\r\n", "8.8.8.8"},
		{"8.8.8.8\x00evil", "8.8.8.8evil"},
		{"  spaces  ", "spaces"},
	}

	for _, tc := range tests {
		got := sanitizeWhoisQuery(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeWhoisQuery(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIsAllowedWhoisServer(t *testing.T) {
	tests := []struct {
		server string
		want   bool
	}{
		{"whois.arin.net", true},
		{"whois.ripe.net", true},
		{"evil.server.com", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := (allowedWhoisServers[tc.server]); got != tc.want {
			t.Errorf("isAllowed(%q) = %v, want %v", tc.server, got, tc.want)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10, 60*time.Second)

	// Should allow up to 10
	for i := 0; i < 10; i++ {
		if !limiter.Allow() {
			t.Errorf("rate limit should allow query %d", i+1)
		}
	}
	// 11th should be rejected
	if limiter.Allow() {
		t.Error("rate limit should reject 11th query")
	}
}

func TestRateLimiterReset(t *testing.T) {
	limiter := NewRateLimiter(2, 60*time.Second)

	limiter.Allow()
	limiter.Allow()
	if limiter.Allow() {
		t.Error("should be rate limited")
	}

	limiter.Reset()
	if !limiter.Allow() {
		t.Error("should be allowed after reset")
	}
}
