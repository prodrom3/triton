// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// releasePublicKey is the base64-encoded ed25519 public key (32 bytes) used to
// verify the signature over the SHA256SUMS release asset. When empty, signature
// verification is skipped and only checksum verification is enforced, which
// protects against corrupted or truncated downloads but not against a tampered
// release. Set this to the project signing key to enable full verification.
// See docs/RELEASING.md for how to generate the keypair and sign releases.
const releasePublicKey = ""

const (
	checksumsAsset    = "SHA256SUMS"
	checksumsSigAsset = "SHA256SUMS.sig"
)

// signatureConfigured reports whether release-signature verification is enabled.
func signatureConfigured() bool {
	return strings.TrimSpace(releasePublicKey) != ""
}

// verifyChecksumsSignature verifies that sigData is a valid ed25519 signature
// over sumsData using the embedded release public key. It returns nil when no
// key is configured (signature verification disabled).
func verifyChecksumsSignature(sumsData, sigData []byte) error {
	if !signatureConfigured() {
		return nil
	}
	return verifySignatureWith(releasePublicKey, sumsData, sigData)
}

// verifySignatureWith verifies an ed25519 signature over data using a
// base64-encoded public key.
func verifySignatureWith(pubB64 string, data, sigData []byte) error {
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return fmt.Errorf("invalid embedded public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(keyBytes), data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// checksumFor extracts the expected hex SHA-256 for the named file from the
// contents of a SHA256SUMS file. Lines are of the form "<hex>  <filename>".
func checksumFor(sumsData []byte, filename string) (string, error) {
	for _, line := range strings.Split(string(sumsData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// The filename may be prefixed with '*' (binary mode) in some tools.
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == filename {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %q", filename)
}

// verifyAsset checks that data hashes to the expected hex SHA-256 digest.
func verifyAsset(data []byte, wantHex string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(wantHex)))
	if err != nil {
		return fmt.Errorf("malformed expected checksum: %w", err)
	}
	gotRaw := sum[:]
	if len(want) != len(gotRaw) || subtle.ConstantTimeCompare(gotRaw, want) != 1 {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, strings.ToLower(strings.TrimSpace(wantHex)))
	}
	return nil
}

// compareSemver compares two dotted version strings numerically.
// It returns -1 if a < b, 0 if equal, and 1 if a > b. A leading "v" is ignored
// and any pre-release/build suffix after '-' or '+' is dropped before compare.
func compareSemver(a, b string) int {
	pa := parseSemver(a)
	pb := parseSemver(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			n = 0
		}
		out[i] = n
	}
	return out
}
