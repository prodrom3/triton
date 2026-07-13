// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package ping

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPPingOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	res := TCPPing(context.Background(), nil, "127.0.0.1", port, 3, 2*time.Second)
	if res.Protocol != "tcp" {
		t.Errorf("protocol = %q want tcp", res.Protocol)
	}
	if res.Loss != 0 {
		t.Errorf("expected 0%% loss to open port, got %.0f", res.Loss)
	}
	if res.Avg == nil {
		t.Error("expected avg RTT")
	}
}

func TestTCPPingClosedPort(t *testing.T) {
	// Port 1 on loopback is almost certainly closed.
	res := TCPPing(context.Background(), nil, "127.0.0.1", 1, 2, 500*time.Millisecond)
	if res.Loss != 100 {
		t.Errorf("expected 100%% loss to closed port, got %.0f", res.Loss)
	}
}

func TestCalcLoss(t *testing.T) {
	cases := []struct {
		total, fail int
		want        float64
	}{
		{0, 0, 0}, {4, 0, 0}, {4, 2, 50}, {3, 3, 100},
	}
	for _, c := range cases {
		if got := calcLoss(c.total, c.fail); got != c.want {
			t.Errorf("calcLoss(%d,%d)=%.0f want %.0f", c.total, c.fail, got, c.want)
		}
	}
}

func TestICMPPingLoopback(t *testing.T) {
	res := ICMPPing(context.Background(), "127.0.0.1", 2, time.Second)
	if res.Protocol != "icmp" {
		t.Errorf("protocol = %q want icmp", res.Protocol)
	}
	if res.Error != nil {
		// Unprivileged ICMP is not always permitted (CI, restricted hosts).
		t.Skipf("ICMP not permitted in this environment: %s", *res.Error)
	}
	if res.Loss != 0 {
		t.Errorf("expected 0%% loss pinging loopback, got %.0f", res.Loss)
	}
	if res.Avg == nil {
		t.Error("expected avg RTT from loopback ICMP")
	}
}

func TestICMPPingInvalidIP(t *testing.T) {
	res := ICMPPing(context.Background(), "not-an-ip", 1, time.Second)
	if res.Error == nil {
		t.Error("expected error for invalid IP")
	}
}
