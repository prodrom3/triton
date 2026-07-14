// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"github.com/prodrom3/triton/internal/network"
)

// tlsProbeVersions are the protocol versions probed for support, low to high.
var tlsProbeVersions = []struct {
	name string
	ver  uint16
}{
	{"TLSv1.0", tls.VersionTLS10},
	{"TLSv1.1", tls.VersionTLS11},
	{"TLSv1.2", tls.VersionTLS12},
	{"TLSv1.3", tls.VersionTLS13},
}

// allCipherIDs returns every cipher suite the Go client can offer, including the
// insecure ones, so a server that only accepts a weak cipher still completes the
// handshake and is recorded as supporting that protocol version. (Go no longer
// offers RC4 at all, so RC4-only servers remain undetectable from stdlib.)
func allCipherIDs() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// probeTLSVersions reports which TLS versions the endpoint accepts, the cipher
// suite negotiated at TLS 1.2, and the peer certificate from the highest
// accepted version. Each version is tried with a separate handshake pinned to
// min == max, offering all cipher suites, without certificate verification (a
// posture check, not a trust check). Detection of TLS 1.0/1.1 is best effort:
// the Go client may not offer the legacy ciphers some old servers require.
func probeTLSVersions(ctx context.Context, dialer *network.Dialer, addr, sniHost string, timeout time.Duration) (accepted []string, cipher string, cert *x509.Certificate) {
	all := allCipherIDs()
	for _, pv := range tlsProbeVersions {
		conn, err := tlsHandshakePinned(ctx, dialer, addr, sniHost, timeout, pv.ver, all)
		if err != nil {
			continue
		}
		accepted = append(accepted, pv.name)
		st := conn.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			cert = st.PeerCertificates[0] // ascending loop leaves the highest version's cert
		}
		if pv.ver == tls.VersionTLS12 {
			cipher = tls.CipherSuiteName(st.CipherSuite)
		}
		conn.Close()
	}
	return accepted, cipher, cert
}

// tlsHandshakePinned dials addr and performs a TLS handshake pinned to exactly
// one protocol version, offering the given cipher suites. The caller closes the
// returned connection.
func tlsHandshakePinned(ctx context.Context, dialer *network.Dialer, addr, sniHost string, timeout time.Duration, version uint16, ciphers []uint16) (*tls.Conn, error) {
	dialer = network.OrDefault(dialer, timeout)
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else if timeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(timeout))
	}
	conn := tls.Client(raw, &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         sniHost,
		CipherSuites:       ciphers,
		InsecureSkipVerify: true, // #nosec G402 -- probing accepted protocol versions and ciphers, not verifying trust
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// orderedVersions returns the version names present in set, ordered low to high.
func orderedVersions(set map[string]bool) []string {
	var out []string
	for _, pv := range tlsProbeVersions {
		if set[pv.name] {
			out = append(out, pv.name)
		}
	}
	return out
}

// isWeakCipher reports whether a cipher suite name indicates a weak negotiation:
// RC4 or 3DES, CBC-mode suites, or non-forward-secret RSA key exchange.
func isWeakCipher(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToUpper(name)
	switch {
	case strings.Contains(n, "RC4"), strings.Contains(n, "3DES"), strings.Contains(n, "_CBC_"):
		return true
	case strings.HasPrefix(n, "TLS_RSA_"): // static RSA key exchange, no forward secrecy
		return true
	}
	return false
}

// tlsGrade summarizes the posture as a letter grade. It is intentionally simple:
// expired certs, weak ciphers, and TLS 1.0 support fail; TLS 1.1 support is a C;
// TLS 1.2 without 1.3 is a B; TLS 1.3 support is an A.
func tlsGrade(accepted []string, weakCipher, expired bool) string {
	has := func(v string) bool {
		for _, a := range accepted {
			if a == v {
				return true
			}
		}
		return false
	}
	switch {
	case len(accepted) == 0:
		return ""
	case expired, weakCipher, has("TLSv1.0"):
		return "F"
	case has("TLSv1.1"):
		return "C"
	case has("TLSv1.3"):
		return "A"
	case has("TLSv1.2"):
		return "B"
	default:
		return ""
	}
}
