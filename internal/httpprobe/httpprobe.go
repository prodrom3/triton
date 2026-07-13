// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package httpprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
)

// Probe sends an HTTP(S) request to the target and collects response metadata.
func Probe(ctx context.Context, dialer *network.Dialer, host, ip string, port int, timeout time.Duration) models.HTTPProbeResult {
	dialer = network.OrDefault(dialer, timeout)
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402 -- reconnaissance tool inspects self-signed and invalid certs by design
			ServerName:         host,
		},
		DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
			// Force connection to the resolved IP, not the hostname, and route
			// through the shared dialer so proxy, rate limiting, and retries apply.
			target := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
			return dialer.DialContext(ctx, "tcp", target)
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return models.HTTPProbeResult{
			URL:   url,
			Error: models.Ptr(err.Error()),
		}
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return models.HTTPProbeResult{
			URL:   url,
			Error: models.Ptr(err.Error()),
		}
	}
	defer resp.Body.Close()

	result := models.HTTPProbeResult{
		URL:        url,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
	}

	// Capture server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = &server
	}

	// Capture redirect chain
	if resp.Request.URL.String() != url {
		final := resp.Request.URL.String()
		result.FinalURL = &final
	}

	// Check security headers
	result.SecurityHeaders = checkSecurityHeaders(resp.Header)

	return result
}

func checkSecurityHeaders(h http.Header) models.SecurityHeaders {
	sh := models.SecurityHeaders{}

	if v := h.Get("Strict-Transport-Security"); v != "" {
		sh.HSTS = &v
	}
	if v := h.Get("Content-Security-Policy"); v != "" {
		sh.CSP = &v
	}
	if v := h.Get("X-Frame-Options"); v != "" {
		sh.XFrameOptions = &v
	}
	if v := h.Get("X-Content-Type-Options"); v != "" {
		sh.XContentTypeOptions = &v
	}
	if v := h.Get("X-XSS-Protection"); v != "" {
		sh.XXSSProtection = &v
	}

	// Build list of missing important headers
	var missing []string
	if sh.HSTS == nil {
		missing = append(missing, "Strict-Transport-Security")
	}
	if sh.XFrameOptions == nil {
		missing = append(missing, "X-Frame-Options")
	}
	if sh.XContentTypeOptions == nil {
		missing = append(missing, "X-Content-Type-Options")
	}
	if len(missing) > 0 {
		s := strings.Join(missing, ", ")
		sh.Missing = &s
	}

	return sh
}
