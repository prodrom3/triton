// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestEndToEndScan builds the actual binary and drives a full scan against a
// local listener, exercising flag parsing, the pipeline, and JSON output end to
// end. It is skipped under -short.
func TestEndToEndScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end binary test in -short mode")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "triton")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// --version works.
	if out, err := exec.Command(bin, "--version").CombinedOutput(); err != nil {
		t.Fatalf("--version failed: %v\n%s", err, out)
	} else if !strings.Contains(string(out), "triton") {
		t.Errorf("unexpected --version output: %q", out)
	}

	// An open local port shows up in the JSON scan.
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

	out, _ := exec.Command(bin, "--no-traceroute", "--ports", strconv.Itoa(port),
		"--json", "--quiet", "127.0.0.1").CombinedOutput()
	s := string(out)
	if !strings.Contains(s, `"port": `+strconv.Itoa(port)) || !strings.Contains(s, `"open": true`) {
		t.Errorf("expected open port %d in JSON output, got:\n%s", port, s)
	}

	// A shell completion script is emitted.
	if out, err := exec.Command(bin, "--completion", "bash").CombinedOutput(); err != nil {
		t.Fatalf("--completion failed: %v\n%s", err, out)
	} else if !strings.Contains(string(out), "complete -F _triton triton") {
		t.Errorf("unexpected bash completion output")
	}

	// --fail-on=changed without --diff must be rejected, not silently accepted.
	foOut, foErr := exec.Command(bin, "--fail-on", "changed", "127.0.0.1").CombinedOutput()
	if foErr == nil {
		t.Error("--fail-on=changed without --diff should exit non-zero")
	}
	if !strings.Contains(string(foOut), "requires --diff") {
		t.Errorf("expected a 'requires --diff' error, got: %s", foOut)
	}
}
