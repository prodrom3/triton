// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestParseProxy(t *testing.T) {
	valid := []struct {
		in         string
		wantScheme string
		wantUser   string
	}{
		{"socks5://127.0.0.1:1080", "socks5", ""},
		{"socks5h://host:1080", "socks5", ""},
		{"http://proxy:3128", "http", ""},
		{"https://proxy:3128", "http", ""},
		{"socks5://user:pass@host:1080", "socks5", "user"},
	}
	for _, c := range valid {
		p, err := ParseProxy(c.in)
		if err != nil {
			t.Errorf("ParseProxy(%q) unexpected error: %v", c.in, err)
			continue
		}
		if p.scheme != c.wantScheme || p.user != c.wantUser {
			t.Errorf("ParseProxy(%q) = scheme %q user %q", c.in, p.scheme, p.user)
		}
	}

	invalid := []string{
		"ftp://host:21", // unsupported scheme
		"socks5://host", // missing port
		"://noscheme:1", // no scheme
		"http://",       // no host
	}
	for _, in := range invalid {
		if _, err := ParseProxy(in); err == nil {
			t.Errorf("ParseProxy(%q) expected error, got nil", in)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	private := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "::1", "fe80::1", "0.0.0.0", "fc00::1", "224.0.0.1",
		"100.64.0.1", "100.127.255.255", "0.0.0.1", "255.255.255.255"}
	for _, ip := range private {
		if !IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = false, want true", ip)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, ip := range public {
		if IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) = true, want false", ip)
		}
	}
	if IsPrivate("not-an-ip") {
		t.Error("IsPrivate on invalid input should be false")
	}
}

func TestIsIPv4(t *testing.T) {
	if !IsIPv4("1.2.3.4") {
		t.Error("1.2.3.4 should be IPv4")
	}
	if IsIPv4("::1") || IsIPv4("2001:db8::1") {
		t.Error("IPv6 must not be reported as IPv4")
	}
	if IsIPv4("bogus") {
		t.Error("invalid input must not be IPv4")
	}
}

func TestFilterByFamily(t *testing.T) {
	ips := []string{"1.2.3.4", "2001:db8::1", "5.6.7.8", "::1"}
	if got := FilterByFamily(ips, 0); len(got) != 4 {
		t.Errorf("family 0 should keep all, got %v", got)
	}
	v4 := FilterByFamily(ips, 4)
	if len(v4) != 2 || v4[0] != "1.2.3.4" {
		t.Errorf("family 4 filter wrong: %v", v4)
	}
	v6 := FilterByFamily(ips, 6)
	if len(v6) != 2 || v6[0] != "2001:db8::1" {
		t.Errorf("family 6 filter wrong: %v", v6)
	}
}

func TestDialerDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("hello"))
		c.Close()
	}()

	d := NewDialer(DialOptions{Timeout: 2 * time.Second})
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q", buf)
	}
}

// startSOCKS5 spins up a minimal no-auth SOCKS5 server that connects to the
// requested target and pipes bytes. It returns the proxy address.
func startSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(conn)
		}
	}()
	return ln.Addr().String()
}

func serveSOCKS5(conn net.Conn) {
	defer conn.Close()
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// Request: VER CMD RSV ATYP ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		b := make([]byte, int(l[0]))
		io.ReadFull(conn, b)
		host = string(b)
	default:
		return
	}
	portB := make([]byte, 2)
	io.ReadFull(conn, portB)
	port := int(portB[0])<<8 | int(portB[1])

	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success

	go io.Copy(target, conn)
	io.Copy(conn, target)
}

func TestDialerThroughSOCKS5(t *testing.T) {
	// Target echo server.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	proxyAddr := startSOCKS5(t)
	p, err := ParseProxy("socks5://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(DialOptions{Timeout: 3 * time.Second, Proxy: p})

	conn, err := d.DialContext(context.Background(), "tcp", target.Addr().String())
	if err != nil {
		t.Fatalf("dial through socks5 failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo through proxy got %q", buf)
	}
}

// TestHTTPConnectPreservesBufferedBytes verifies that a server-speaks-first
// banner coalesced with the CONNECT 200 response is not lost.
func TestHTTPConnectPreservesBufferedBytes(t *testing.T) {
	const banner = "SSH-2.0-OpenSSH_9.0"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for { // consume the CONNECT request headers
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		// Coalesce the 200 response and the target banner into one write.
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n" + banner))
		// Keep the tunnel open briefly so the client can read.
		buf := make([]byte, 1)
		c.Read(buf)
	}()

	p, err := ParseProxy("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	d := NewDialer(DialOptions{Timeout: 3 * time.Second, Proxy: p})
	conn, err := d.DialContext(context.Background(), "tcp", "10.0.0.1:22")
	if err != nil {
		t.Fatalf("connect through http proxy failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len(banner))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading banner: %v", err)
	}
	if string(buf) != banner {
		t.Errorf("buffered banner lost: got %q want %q", buf, banner)
	}
}
