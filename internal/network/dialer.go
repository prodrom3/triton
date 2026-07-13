// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// DialOptions configures a Dialer.
type DialOptions struct {
	Timeout time.Duration
	Retries int          // extra attempts when a connection times out
	Rate    float64      // global connections per second; 0 means unlimited
	Proxy   *ProxyConfig // optional proxy; nil dials directly
}

// Dialer is a context-aware TCP dialer shared by every probe. It applies an
// optional global rate limit, retries on timeout, and routes through a SOCKS5
// or HTTP CONNECT proxy when configured. The zero value is not usable; call
// NewDialer.
type Dialer struct {
	timeout  time.Duration
	retries  int
	throttle *throttle
	proxy    *ProxyConfig
}

// OrDefault returns d, or a plain direct dialer with the given timeout when d
// is nil. Probe functions use it so a nil dialer is always safe.
func OrDefault(d *Dialer, timeout time.Duration) *Dialer {
	if d != nil {
		return d
	}
	return NewDialer(DialOptions{Timeout: timeout})
}

// NewDialer builds a Dialer from options.
func NewDialer(opts DialOptions) *Dialer {
	d := &Dialer{
		timeout: opts.Timeout,
		retries: opts.Retries,
		proxy:   opts.Proxy,
	}
	if opts.Rate > 0 {
		d.throttle = newThrottle(opts.Rate)
	}
	return d
}

// DialContext dials addr, honoring the rate limit, retry, and proxy settings.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	attempts := d.retries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		if d.throttle != nil {
			if err := d.throttle.wait(ctx); err != nil {
				return nil, err
			}
		}
		conn, err := d.dialOnce(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// Retry only on timeouts. A refused connection is a definitive result
		// (for a port scan it means "closed"), so retrying would be wrong.
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (d *Dialer) dialOnce(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.proxy != nil {
		return d.proxy.dial(ctx, addr, d.timeout)
	}
	nd := &net.Dialer{Timeout: d.timeout}
	return nd.DialContext(ctx, network, addr)
}

// throttle is a single-token-bucket rate limiter.
type throttle struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newThrottle(perSec float64) *throttle {
	return &throttle{interval: time.Duration(float64(time.Second) / perSec)}
}

func (t *throttle) wait(ctx context.Context) error {
	t.mu.Lock()
	now := time.Now()
	if t.next.Before(now) {
		t.next = now
	}
	delay := t.next.Sub(now)
	t.next = t.next.Add(t.interval)
	t.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ProxyConfig describes a SOCKS5 or HTTP CONNECT proxy.
type ProxyConfig struct {
	scheme string // "socks5" or "http"
	host   string // host:port of the proxy
	user   string
	pass   string
}

// ParseProxy parses a proxy URL of the form socks5://[user:pass@]host:port or
// http://[user:pass@]host:port (https is treated as an HTTP CONNECT proxy).
func ParseProxy(raw string) (*ProxyConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	var scheme string
	switch u.Scheme {
	case "socks5", "socks5h":
		scheme = "socks5"
	case "http", "https":
		scheme = "http"
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5:// or http://)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy URL is missing host:port")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("proxy URL must include a port: %w", err)
	}
	pc := &ProxyConfig{scheme: scheme, host: u.Host}
	if u.User != nil {
		pc.user = u.User.Username()
		pc.pass, _ = u.User.Password()
	}
	return pc, nil
}

// proxyHandshakeTimeout bounds a proxy handshake when neither the context nor
// the dialer supplies a deadline, so a proxy that accepts but never replies
// cannot hang the read indefinitely.
const proxyHandshakeTimeout = 30 * time.Second

func (p *ProxyConfig) dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	nd := &net.Dialer{Timeout: timeout}
	conn, err := nd.DialContext(ctx, "tcp", p.host)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}

	// Always bound the handshake with a deadline.
	hsDeadline := time.Now().Add(proxyHandshakeTimeout)
	if deadline, ok := ctx.Deadline(); ok {
		hsDeadline = deadline
	} else if timeout > 0 {
		hsDeadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(hsDeadline)

	result := net.Conn(conn)
	var herr error
	if p.scheme == "socks5" {
		herr = p.socks5Handshake(conn, addr)
	} else {
		result, herr = p.httpConnect(conn, addr)
	}
	if herr != nil {
		conn.Close()
		return nil, herr
	}
	// Clear the handshake deadline; each probe manages its own timeouts.
	_ = conn.SetDeadline(time.Time{})
	return result, nil
}

// prefixConn prepends already-buffered bytes in front of a net.Conn's stream.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (p *ProxyConfig) socks5Handshake(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("socks5: invalid port %q", portStr)
	}

	methods := []byte{0x00}
	if p.user != "" {
		methods = []byte{0x00, 0x02}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return err
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected version %d", sel[0])
	}
	switch sel[1] {
	case 0x00:
		// no authentication
	case 0x02:
		if err := p.socks5Auth(conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5: proxy rejected offered auth methods")
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	case ip != nil:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	default:
		if len(host) > 255 {
			return fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect rejected (reply code %d)", head[1])
	}
	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		addrLen = int(l[0])
	default:
		return fmt.Errorf("socks5: unexpected address type %d", head[3])
	}
	// Discard BND.ADDR + BND.PORT.
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return err
	}
	return nil
}

func (p *ProxyConfig) socks5Auth(conn net.Conn) error {
	if len(p.user) > 255 || len(p.pass) > 255 {
		return fmt.Errorf("socks5: credentials too long")
	}
	msg := []byte{0x01, byte(len(p.user))}
	msg = append(msg, p.user...)
	msg = append(msg, byte(len(p.pass)))
	msg = append(msg, p.pass...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed")
	}
	return nil
}

func (p *ProxyConfig) httpConnect(conn net.Conn, addr string) (net.Conn, error) {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if p.user != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.user + ":" + p.pass))
		req += "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http proxy CONNECT failed: %s", resp.Status)
	}
	// A server-speaks-first target (SSH, SMTP, etc.) may have its banner coalesced
	// with the CONNECT response into bufio's buffer. Preserve any such read-ahead
	// bytes so the caller's first Read does not lose them.
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		return &prefixConn{Conn: conn, prefix: buf}, nil
	}
	return conn, nil
}
