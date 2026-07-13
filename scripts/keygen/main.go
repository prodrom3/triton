// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

// Command keygen generates an ed25519 keypair for signing release checksum
// manifests. Run it once, store the private key as a repository secret named
// RELEASE_SIGNING_KEY, and paste the public key into
// internal/updater/verify.go (const releasePublicKey). See docs/RELEASING.md.
//
// Usage:
//
//	go run ./scripts/keygen
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen failed:", err)
		os.Exit(1)
	}
	fmt.Println("Public key (paste into internal/updater/verify.go releasePublicKey):")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("Private key (store as the RELEASE_SIGNING_KEY repository secret; keep it secret):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
}
