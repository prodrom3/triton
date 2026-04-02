// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package tracer

import (
	"testing"
)

func TestParseRTT(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"1.234", 1.234},
		{"<1", 1.0},
		{"0.5", 0.5},
		{"abc", 0.0},
	}

	for _, tc := range tests {
		got := parseRTT(tc.input)
		if got != tc.want {
			t.Errorf("parseRTT(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseSystemOutputLinux(t *testing.T) {
	output := ` 1  192.168.1.1  1.234 ms
 2  10.0.0.1  5.678 ms
 3  8.8.8.8  10.123 ms
`
	hops := parseSystemOutput(output)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}

	if hops[0].TTL != 1 || hops[0].IP != "192.168.1.1" {
		t.Errorf("hop 0: got TTL=%d IP=%s", hops[0].TTL, hops[0].IP)
	}
	if hops[1].TTL != 2 || hops[1].IP != "10.0.0.1" {
		t.Errorf("hop 1: got TTL=%d IP=%s", hops[1].TTL, hops[1].IP)
	}
	if hops[2].RTT == nil || *hops[2].RTT != 10.123 {
		t.Errorf("hop 2: expected RTT 10.123")
	}
}

func TestParseSystemOutputLinuxTimeout(t *testing.T) {
	output := ` 1  192.168.1.1  1.234 ms
 2  * * *
 3  8.8.8.8  10.123 ms
`
	hops := parseSystemOutput(output)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops (including timeout), got %d", len(hops))
	}

	if hops[1].TTL != 2 || hops[1].IP != "*" {
		t.Errorf("hop 1: expected TTL=2 IP=*, got TTL=%d IP=%s", hops[1].TTL, hops[1].IP)
	}
	if hops[1].RTT != nil {
		t.Error("timed-out hop should have nil RTT")
	}
}

func TestParseSystemOutputWindows(t *testing.T) {
	output := `Tracing route to 8.8.8.8
  1     1 ms     1 ms     1 ms  192.168.1.1
  2     5 ms     6 ms     5 ms  10.0.0.1
  3    <1 ms    <1 ms    <1 ms  8.8.8.8
`
	hops := parseSystemOutput(output)
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}

	if hops[0].TTL != 1 || hops[0].IP != "192.168.1.1" {
		t.Errorf("hop 0: got TTL=%d IP=%s", hops[0].TTL, hops[0].IP)
	}
	if hops[2].RTT == nil || *hops[2].RTT != 1.0 {
		t.Errorf("hop 2: expected RTT 1.0 for <1 ms, got %v", hops[2].RTT)
	}
}

func TestParseSystemOutputEmpty(t *testing.T) {
	hops := parseSystemOutput("")
	if len(hops) != 0 {
		t.Errorf("expected 0 hops for empty output, got %d", len(hops))
	}
}
