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
	"flag"
	"fmt"
	"os"
)

func main() {
	pubOut := flag.String("pub-out", "", "write the base64 public key to this file instead of stdout")
	privOut := flag.String("priv-out", "", "write the base64 private key to this file instead of stdout (keep it out of version control)")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen failed:", err)
		os.Exit(1)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)

	if *pubOut != "" {
		if err := os.WriteFile(*pubOut, []byte(pubB64+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write pub:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Public key (paste into internal/updater/verify.go releasePublicKey):")
		fmt.Println(pubB64)
		fmt.Println()
	}

	if *privOut != "" {
		if err := os.WriteFile(*privOut, []byte(privB64+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write priv:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Private key (store as the RELEASE_SIGNING_KEY repository secret; keep it secret):")
		fmt.Println(privB64)
	}
}
