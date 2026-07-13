// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import "testing"

func TestNormalizeResolverAddr(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":                   "8.8.8.8:53",
		"8.8.8.8:5353":              "8.8.8.8:5353",
		"8.8.8.8:":                  "8.8.8.8:53",
		"2001:4860:4860::8888":      "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]":    "[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8888]:53": "[2001:4860:4860::8888]:53",
		"dns.example.com":           "dns.example.com:53",
		"dns.example.com:5353":      "dns.example.com:5353",
	}
	for in, want := range cases {
		if got := normalizeResolverAddr(in); got != want {
			t.Errorf("normalizeResolverAddr(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNewResolverEmptyIsDefault(t *testing.T) {
	if NewResolver("") == nil {
		t.Error("empty resolver should return the default, not nil")
	}
}
