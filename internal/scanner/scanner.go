// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
)

// CommonPorts maps port numbers to service names.
var CommonPorts = map[int]string{
	21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https",
	993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
	5432: "postgres", 8080: "http-alt", 8443: "https-alt",
}

var defaultPorts = []int{21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443}

var httpPorts = map[int]bool{80: true, 8080: true, 8443: true, 443: true}

func serviceName(port int) string {
	if s, ok := CommonPorts[port]; ok {
		return s
	}
	return "unknown"
}

func scanSinglePort(ctx context.Context, dialer *network.Dialer, ip string, port int, timeout time.Duration, grab bool, hostname string) models.PortResult {
	service := serviceName(port)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return models.PortResult{Port: port, Open: false, Service: service}
	}
	defer conn.Close()

	var banner *string
	if grab {
		host := hostname
		if host == "" {
			host = ip
		}
		banner = grabBanner(conn, host, port, timeout)
	}

	return models.PortResult{Port: port, Open: true, Service: service, Banner: banner}
}

func grabBanner(conn net.Conn, host string, port int, timeout time.Duration) *string {
	bannerTimeout := timeout
	if bannerTimeout > 3*time.Second {
		bannerTimeout = 3 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	if httpPorts[port] {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	text := strings.TrimSpace(string(buf[:n]))
	if idx := strings.Index(text, "\n"); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}
	if len(text) > 200 {
		text = text[:200]
	}
	return &text
}

// ScanPorts scans multiple TCP ports concurrently.
// Only open ports are returned; closedCount gives the number of closed ports.
// The hostname parameter is used for HTTP Host headers during banner grabbing.
func ScanPorts(ctx context.Context, dialer *network.Dialer, ip string, ports []int, timeout time.Duration, grabBanners bool, workers int, hostname string) (open []models.PortResult, closedCount int) {
	dialer = network.OrDefault(dialer, timeout)
	if len(ports) == 0 {
		ports = defaultPorts
	}
	if workers <= 0 {
		workers = 16
	}

	var (
		mu     sync.Mutex
		closed int
		wg     sync.WaitGroup
		sem    = make(chan struct{}, workers)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			r := scanSinglePort(ctx, dialer, ip, p, timeout, grabBanners, hostname)
			mu.Lock()
			if r.Open {
				open = append(open, r)
			} else {
				closed++
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})
	closedCount = closed
	return
}

// tlsHandshake dials addr through the shared dialer and performs a TLS
// handshake, returning the established *tls.Conn. The caller closes it.
func tlsHandshake(ctx context.Context, dialer *network.Dialer, addr, host string, timeout time.Duration, insecure bool) (*tls.Conn, error) {
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
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: insecure, // #nosec G402 -- recon tool falls back to an unverified handshake to read self-signed/invalid certs
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// TLSCertInfo inspects the TLS certificate of a host. The connection is made to
// dialIP (the pre-resolved, guard-filtered address) while sniHost is used for
// SNI and certificate name reporting. Separating the two ensures the TLS probe
// connects to the same address that passed the SSRF and family filters, instead
// of re-resolving the hostname at connect time.
func TLSCertInfo(ctx context.Context, dialer *network.Dialer, dialIP, sniHost string, port int, timeout time.Duration) models.TlsCertResult {
	dialer = network.OrDefault(dialer, timeout)
	host := sniHost
	addr := net.JoinHostPort(dialIP, fmt.Sprintf("%d", port))

	// A verified handshake (min TLS 1.2) determines whether the certificate is
	// trusted and provides the primary certificate and version.
	var verifiedCert *x509.Certificate
	var verifiedVersion string
	verified := false
	if conn, err := tlsHandshake(ctx, dialer, addr, host, timeout, false); err == nil {
		st := conn.ConnectionState()
		verified = true
		verifiedVersion = tlsVersionString(st.Version)
		if len(st.PeerCertificates) > 0 {
			verifiedCert = st.PeerCertificates[0]
		}
		conn.Close()
	}

	// Posture probe: which versions are accepted, the negotiated TLS 1.2 cipher,
	// and an (untrusted) certificate. This runs independently of the verified
	// handshake so legacy-only (TLS 1.0/1.1) servers are still assessed.
	accepted, cipher, probeCert := probeTLSVersions(ctx, dialer, addr, host, timeout)

	// Merge the proven verified version so a healthy host is never reported with
	// no accepted protocols if the posture re-probes were interrupted.
	set := map[string]bool{}
	for _, v := range accepted {
		set[v] = true
	}
	if verifiedVersion != "" {
		set[verifiedVersion] = true
	}
	accepted = orderedVersions(set)

	if len(accepted) == 0 {
		errStr := "TLS handshake failed for all supported versions"
		return models.TlsCertResult{Host: host, Success: false, Error: &errStr}
	}

	res := models.TlsCertResult{
		Host:              host,
		Success:           true,
		SelfSigned:        !verified,
		AcceptedProtocols: accepted,
	}
	for _, p := range accepted {
		if p == "TLSv1.0" || p == "TLSv1.1" {
			res.WeakProtocols = append(res.WeakProtocols, p)
		}
	}
	highest := accepted[len(accepted)-1]
	res.Protocol = &highest

	// Grade on the negotiated cipher: with all cipher suites offered, the server
	// picks its preferred one, so a server that only supports (or prefers) a weak
	// cipher reveals it, while a strong server that merely tolerates a legacy
	// cipher for old clients is not penalized.
	if cipher != "" {
		res.CipherSuite = &cipher
		res.WeakCipher = isWeakCipher(cipher)
	}

	cert := verifiedCert
	if cert == nil {
		cert = probeCert
	}
	if cert != nil {
		issuer := cert.Issuer.String()
		subject := cert.Subject.String()
		notBefore := cert.NotBefore.Format(time.RFC3339)
		notAfter := cert.NotAfter.Format(time.RFC3339)
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		res.Issuer = &issuer
		res.Subject = &subject
		res.NotBefore = &notBefore
		res.NotAfter = &notAfter
		res.DaysUntilExpiry = &days
		res.Expired = time.Now().After(cert.NotAfter)
		res.SANs = append([]string(nil), cert.DNSNames...)
	} else {
		issuer := "Unverified (self-signed or invalid)"
		subject := "Unverified"
		res.Issuer = &issuer
		res.Subject = &subject
	}

	res.Grade = tlsGrade(accepted, res.WeakCipher, res.Expired)
	return res
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}
