// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestScanPortsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	open, closed := ScanPorts(ctx, "127.0.0.1", []int{port}, 2*time.Second, false, 4, "")

	if len(open) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(open))
	}
	if open[0].Port != port {
		t.Errorf("expected port %d, got %d", port, open[0].Port)
	}
	if closed != 0 {
		t.Errorf("expected 0 closed, got %d", closed)
	}
}

func TestScanPortsClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ctx := context.Background()
	open, closed := ScanPorts(ctx, "127.0.0.1", []int{port}, 1*time.Second, false, 4, "")

	if len(open) != 0 {
		t.Errorf("expected 0 open ports, got %d", len(open))
	}
	if closed != 1 {
		t.Errorf("expected 1 closed, got %d", closed)
	}
}

func TestScanPortsBannerGrab(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	open, _ := ScanPorts(ctx, "127.0.0.1", []int{port}, 2*time.Second, true, 4, "")

	if len(open) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(open))
	}
	if open[0].Banner == nil {
		t.Fatal("expected banner")
	}
	if *open[0].Banner != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("unexpected banner: %s", *open[0].Banner)
	}
}

func TestScanPortsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	open, closed := ScanPorts(ctx, "192.0.2.1", []int{80, 443}, 5*time.Second, false, 4, "")
	total := len(open) + closed
	if total != 2 {
		t.Errorf("expected 2 total results, got %d", total)
	}
}

func TestScanPortsSorted(t *testing.T) {
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()
	go func() { conn, _ := ln1.Accept(); conn.Close() }()
	go func() { conn, _ := ln2.Accept(); conn.Close() }()

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	open, _ := ScanPorts(ctx, "127.0.0.1", []int{port2, port1}, 2*time.Second, false, 4, "")

	if len(open) != 2 {
		t.Fatalf("expected 2 open, got %d", len(open))
	}
	if open[0].Port > open[1].Port {
		t.Error("expected ports sorted ascending")
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLSv1.0"},
		{tls.VersionTLS11, "TLSv1.1"},
		{tls.VersionTLS12, "TLSv1.2"},
		{tls.VersionTLS13, "TLSv1.3"},
		{0x0000, "TLS 0x0000"},
	}
	for _, tc := range tests {
		got := tlsVersionString(tc.version)
		if got != tc.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestServiceName(t *testing.T) {
	if got := serviceName(80); got != "http" {
		t.Errorf("expected http, got %s", got)
	}
	if got := serviceName(443); got != "https" {
		t.Errorf("expected https, got %s", got)
	}
	if got := serviceName(99999); got != "unknown" {
		t.Errorf("expected unknown, got %s", got)
	}
}

func TestScanPortsIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	defer ln.Close()
	go func() { conn, _ := ln.Accept(); conn.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	open, _ := ScanPorts(ctx, "::1", []int{port}, 2*time.Second, false, 4, "")

	if len(open) != 1 {
		t.Errorf("expected 1 open port on IPv6, got %d", len(open))
	}
}

func TestTLSCertInfoSelfSigned(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"localhost", "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Keep accepted connections open long enough for the TLS handshake to complete
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Hold connection open briefly so client can complete handshake
				buf := make([]byte, 1)
				c.Read(buf)
				c.Close()
			}(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	result := TLSCertInfo(ctx, "127.0.0.1", port, 5*time.Second)

	if !result.Success {
		var errStr string
		if result.Error != nil {
			errStr = *result.Error
		}
		t.Fatalf("expected success, got error: %s", errStr)
	}
	if !result.SelfSigned {
		t.Error("expected self-signed flag")
	}
}

func TestTLSCertInfoConnectionRefused(t *testing.T) {
	ctx := context.Background()
	result := TLSCertInfo(ctx, "127.0.0.1", 1, 1*time.Second)
	if result.Success {
		t.Error("expected failure for refused connection")
	}
	if result.Error == nil {
		t.Error("expected error message")
	}
}
