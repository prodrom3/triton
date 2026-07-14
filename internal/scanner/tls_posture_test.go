// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package scanner

import "testing"

func TestIsWeakCipher(t *testing.T) {
	weak := []string{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	}
	for _, c := range weak {
		if !isWeakCipher(c) {
			t.Errorf("isWeakCipher(%q) = false, want true", c)
		}
	}
	strong := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_AES_128_GCM_SHA256",
		"TLS_CHACHA20_POLY1305_SHA256",
		"",
	}
	for _, c := range strong {
		if isWeakCipher(c) {
			t.Errorf("isWeakCipher(%q) = true, want false", c)
		}
	}
}

func TestTLSGrade(t *testing.T) {
	cases := []struct {
		accepted   []string
		weakCipher bool
		expired    bool
		want       string
	}{
		{[]string{"TLSv1.2", "TLSv1.3"}, false, false, "A"},
		{[]string{"TLSv1.2"}, false, false, "B"},
		{[]string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}, false, false, "C"},
		{[]string{"TLSv1.0", "TLSv1.2"}, false, false, "F"},
		{[]string{"TLSv1.2", "TLSv1.3"}, true, false, "F"},
		{[]string{"TLSv1.2", "TLSv1.3"}, false, true, "F"},
		{nil, false, false, ""},
	}
	for _, c := range cases {
		if got := tlsGrade(c.accepted, c.weakCipher, c.expired); got != c.want {
			t.Errorf("tlsGrade(%v, weak=%v, expired=%v) = %q want %q", c.accepted, c.weakCipher, c.expired, got, c.want)
		}
	}
}
