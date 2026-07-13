// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package tracer

import (
	"strings"
	"testing"
)

// FuzzParseSystemOutput ensures the traceroute output parser never panics on
// arbitrary command output (which originates from an external program).
func FuzzParseSystemOutput(f *testing.F) {
	f.Add(" 1  192.168.1.1  1.234 ms\n 2  * * *\n")
	f.Add("Tracing route to example.com\n  1    <1 ms  <1 ms  <1 ms  10.0.0.1\n")
	f.Add(" 1  2001:db8::1  1.234 ms\n")
	f.Add(" 1  192.168.1.1 (router)  1.234 ms\n")
	f.Add("")
	f.Add("garbage \x00\x1b[31m lines")
	f.Add(strings.Repeat("9", 10000))

	f.Fuzz(func(t *testing.T, out string) {
		hops := parseSystemOutput(out)
		for _, h := range hops {
			if h.TTL < 0 {
				t.Errorf("negative TTL parsed from %q", out)
			}
		}
	})
}
