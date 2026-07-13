// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, ".triton.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"workers":8,"whois":true,"ping_port":8443}`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || f.Workers == nil || *f.Workers != 8 {
		t.Fatalf("workers not loaded: %+v", f)
	}
	if f.Whois == nil || !*f.Whois {
		t.Error("whois not loaded")
	}
	if f.PingPort == nil || *f.PingPort != 8443 {
		t.Error("ping_port not loaded")
	}
}

func TestLoadExplicitMissingIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("expected error for missing explicit config")
	}
}

func TestLoadExplicitInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	os.WriteFile(p, []byte("{not json"), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadHomeFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows

	// No config present: not an error, returns nil.
	if f, err := Load(""); err != nil || f != nil {
		t.Fatalf("missing home config should be (nil,nil), got (%v,%v)", f, err)
	}

	writeConfig(t, home, `{"tls":true}`)
	f, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || f.TLS == nil || !*f.TLS {
		t.Fatalf("home config not loaded: %+v", f)
	}
}

func TestLoadIgnoresUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"workers":2,"totally_unknown_field":123,"nested":{"x":1}}`)
	f, err := Load(p)
	if err != nil {
		t.Fatalf("unknown fields should be tolerated: %v", err)
	}
	if f.Workers == nil || *f.Workers != 2 {
		t.Error("known field not parsed alongside unknown ones")
	}
}
