// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.2.0", 0},
		{"v1.2.0", "1.2.0", 0},
		{"1.2.1", "1.2.0", 1},
		{"1.2.0", "1.2.1", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.2.0-rc1", "1.2.0", 0},
		{"1.2.0", "1.2", 0},
		{"1.3", "1.2.9", 1},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNeedsUpdate(t *testing.T) {
	if NeedsUpdate("dev", "1.0.0") {
		t.Error("dev builds must never auto-update")
	}
	if !NeedsUpdate("1.0.0", "1.0.1") {
		t.Error("1.0.0 -> 1.0.1 should update")
	}
	if NeedsUpdate("1.0.0", "1.0.0") {
		t.Error("equal versions should not update")
	}
	// Downgrade protection: an older "latest" must not trigger an update.
	if NeedsUpdate("1.5.0", "1.4.0") {
		t.Error("downgrade must be rejected")
	}
	if NeedsUpdate("v1.0.0", "v0.9.0") {
		t.Error("downgrade must be rejected (v prefix)")
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte("abc123  triton_1.2.0_linux_amd64.tar.gz\n" +
		"def456 *triton_1.2.0_windows_amd64.zip\n" +
		"# a comment\n")
	got, err := checksumFor(sums, "triton_1.2.0_linux_amd64.tar.gz")
	if err != nil || got != "abc123" {
		t.Fatalf("linux: got %q err %v", got, err)
	}
	got, err = checksumFor(sums, "triton_1.2.0_windows_amd64.zip")
	if err != nil || got != "def456" {
		t.Fatalf("windows (star prefix): got %q err %v", got, err)
	}
	if _, err := checksumFor(sums, "missing.tar.gz"); err == nil {
		t.Error("expected error for missing entry")
	}
}

func TestVerifyAsset(t *testing.T) {
	data := []byte("hello world")
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	if err := verifyAsset(data, hexSum); err != nil {
		t.Errorf("valid checksum rejected: %v", err)
	}
	if err := verifyAsset(data, "UPPER"+hexSum[5:]); err == nil {
		t.Error("expected mismatch error")
	}
	if err := verifyAsset([]byte("tampered"), hexSum); err == nil {
		t.Error("tampered data must fail verification")
	}
}

func TestVerifySignatureWith(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sums := []byte("abc123  triton_1.2.0_linux_amd64.tar.gz\n")
	sig := ed25519.Sign(priv, sums)
	sigB64 := []byte(base64.StdEncoding.EncodeToString(sig))

	if err := verifySignatureWith(pubB64, sums, sigB64); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	// Tampered manifest must fail.
	if err := verifySignatureWith(pubB64, []byte("tampered"), sigB64); err == nil {
		t.Error("tampered manifest must fail signature check")
	}
	// Wrong key must fail.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := verifySignatureWith(base64.StdEncoding.EncodeToString(otherPub), sums, sigB64); err == nil {
		t.Error("wrong key must fail signature check")
	}
}

func TestSignatureNotConfiguredSkips(t *testing.T) {
	// With the default (empty) embedded key, verification is a no-op.
	if signatureConfigured() {
		t.Skip("a release key is configured; skipping the unconfigured-path test")
	}
	if err := verifyChecksumsSignature([]byte("x"), []byte("y")); err != nil {
		t.Errorf("unconfigured signature check should return nil, got %v", err)
	}
}

func TestReadCappedRejectsOversize(t *testing.T) {
	// Content at or below the cap is returned intact.
	ok := bytes.Repeat([]byte("x"), 100)
	got, err := readCapped(bytes.NewReader(ok), 100)
	if err != nil || len(got) != 100 {
		t.Fatalf("at-cap read: err=%v len=%d", err, len(got))
	}
	// Content over the cap must error rather than truncate silently.
	over := bytes.Repeat([]byte("x"), 101)
	if _, err := readCapped(bytes.NewReader(over), 100); err == nil {
		t.Error("expected error for content exceeding the cap")
	}
}
