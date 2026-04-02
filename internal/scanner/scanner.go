// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prodrom3/triton/internal/models"
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

func scanSinglePort(ctx context.Context, ip string, port int, timeout time.Duration, grab bool, hostname string) models.PortResult {
	service := serviceName(port)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	dialer := net.Dialer{Timeout: timeout}
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
		_, _ = conn.Write([]byte(fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)))
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
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, grabBanners bool, workers int, hostname string) (open []models.PortResult, closedCount int) {
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
			r := scanSinglePort(ctx, ip, p, timeout, grabBanners, hostname)
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

// TLSCertInfo inspects the TLS certificate of a host.
func TLSCertInfo(ctx context.Context, host string, port int, timeout time.Duration) models.TlsCertResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host},
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Fallback without verification for self-signed/invalid certs (intentional for recon)
		dialer2 := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: timeout},
			Config: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
				ServerName:         host,
			},
		}
		rawConn2, err2 := dialer2.DialContext(ctx, "tcp", addr)
		if err2 != nil {
			errStr := err2.Error()
			return models.TlsCertResult{Host: host, Success: false, Error: &errStr}
		}
		defer rawConn2.Close()
		tlsConn := rawConn2.(*tls.Conn)
		version := tlsVersionString(tlsConn.ConnectionState().Version)
		issuer := "Unverified (self-signed or invalid)"
		subject := "Unverified"
		return models.TlsCertResult{
			Host:       host,
			Success:    true,
			SelfSigned: true,
			Protocol:   &version,
			Issuer:     &issuer,
			Subject:    &subject,
		}
	}
	defer rawConn.Close()

	tlsConn := rawConn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		errStr := "no peer certificates"
		return models.TlsCertResult{Host: host, Success: false, Error: &errStr}
	}

	cert := state.PeerCertificates[0]
	issuer := cert.Issuer.String()
	subject := cert.Subject.String()
	notBefore := cert.NotBefore.Format(time.RFC3339)
	notAfter := cert.NotAfter.Format(time.RFC3339)
	version := tlsVersionString(state.Version)

	var sans []string
	for _, name := range cert.DNSNames {
		sans = append(sans, name)
	}

	return models.TlsCertResult{
		Host:       host,
		Success:    true,
		Issuer:     &issuer,
		Subject:    &subject,
		NotBefore:  &notBefore,
		NotAfter:   &notAfter,
		SANs:       sans,
		SelfSigned: false,
		Protocol:   &version,
	}
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
