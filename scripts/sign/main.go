// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

// Command sign produces a detached ed25519 signature over a file. The signature
// is written as base64 text, matching what internal/updater verifies against the
// SHA256SUMS release asset. See docs/RELEASING.md.
//
// Usage:
//
//	go run ./scripts/sign -key-env RELEASE_SIGNING_KEY -in SHA256SUMS -out SHA256SUMS.sig
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	keyEnv := flag.String("key-env", "RELEASE_SIGNING_KEY", "env var holding the base64 ed25519 private key")
	in := flag.String("in", "", "file to sign")
	out := flag.String("out", "", "output signature file (base64)")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: sign -key-env ENV -in FILE -out FILE.sig")
		os.Exit(2)
	}

	keyB64 := os.Getenv(*keyEnv)
	if keyB64 == "" {
		fmt.Fprintf(os.Stderr, "environment variable %s is empty\n", *keyEnv)
		os.Exit(1)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid base64 private key:", err)
		os.Exit(1)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "invalid private key size: got %d, want %d\n", len(keyBytes), ed25519.PrivateKeySize)
		os.Exit(1)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read input:", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(keyBytes), data)
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write signature:", err)
		os.Exit(1)
	}
}
