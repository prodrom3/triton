// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"strings"
	"testing"
)

// FuzzSanitizeWhoisQuery ensures the WHOIS query sanitizer never emits control
// characters or CRLF that could enable protocol injection, for any input.
func FuzzSanitizeWhoisQuery(f *testing.F) {
	f.Add("8.8.8.8")
	f.Add("n 1.2.3.4\r\nEXTRA")
	f.Add("\x00\x1b[31m evil")
	f.Add(strings.Repeat("a", 5000))

	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeWhoisQuery(in)
		if strings.ContainsAny(out, "\r\n\x00") {
			t.Errorf("sanitized query still contains CR/LF/NUL: %q -> %q", in, out)
		}
		for _, r := range out {
			if r < 0x20 || r == 0x7f {
				t.Errorf("sanitized query contains control char %#U from %q", r, in)
			}
		}
	})
}
