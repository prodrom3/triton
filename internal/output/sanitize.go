// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package output

import "strings"

// clean strips control characters (including ANSI/terminal escape sequences)
// from a string before it is written to a terminal. Reconnaissance data such
// as service banners, WHOIS fields, TLS certificate names, HTTP headers, DNS
// records, and reverse-DNS hostnames originate from untrusted hosts and can
// carry escape sequences that spoof or manipulate the terminal. Removing all
// control runes (C0 range 0x00-0x1F, DEL, and C1 range 0x80-0x9F) neutralizes
// that vector while leaving ordinary printable text, including Unicode, intact.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// cleanAll applies clean to each element of a slice, returning a new slice.
func cleanAll(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = clean(s)
	}
	return out
}
