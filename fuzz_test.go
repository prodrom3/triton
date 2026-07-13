// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import "testing"

// FuzzParsePorts ensures the port-list parser never panics and never returns
// out-of-range ports for arbitrary input.
func FuzzParsePorts(f *testing.F) {
	f.Add("22,80,443")
	f.Add("1-1000")
	f.Add(",,, 80 ,,")
	f.Add("99999999999999999999")
	f.Add("-5")
	f.Add("")
	f.Add("80,abc,443")

	f.Fuzz(func(t *testing.T, in string) {
		ports, err := parsePorts(in)
		if err != nil {
			return
		}
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Errorf("parsePorts(%q) returned out-of-range port %d", in, p)
			}
		}
	})
}
