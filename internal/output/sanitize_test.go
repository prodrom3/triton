// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package output

import (
	"strings"
	"testing"
)

func TestCleanStripsEscapeSequences(t *testing.T) {
	// A malicious banner attempting to inject an ANSI color/clear sequence.
	in := "Server\x1b[31m\x1b[2J evil\x07\r\n"
	got := clean(in)
	if strings.ContainsAny(got, "\x1b\x07\r\n") {
		t.Fatalf("clean left control chars: %q", got)
	}
	if got != "Server[31m[2J evil" {
		t.Fatalf("unexpected clean output: %q", got)
	}
}

func TestCleanKeepsUnicode(t *testing.T) {
	in := "München café 世界"
	if got := clean(in); got != in {
		t.Fatalf("clean altered printable Unicode: %q", got)
	}
}

func TestCleanAll(t *testing.T) {
	got := cleanAll([]string{"a\x1bb", "c"})
	if got[0] != "ab" || got[1] != "c" {
		t.Fatalf("cleanAll: %v", got)
	}
}
