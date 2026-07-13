// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package httpprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
)

// DefaultUserAgent is sent when no custom User-Agent is configured.
const DefaultUserAgent = "triton/recon"

// maxBodyBytes bounds how much of the response body is read for title and
// technology detection, to keep memory and time bounded on large pages.
const maxBodyBytes = 512 * 1024

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Probe sends an HTTP(S) request to the target and collects response metadata.
// userAgent overrides the default User-Agent; extraHeaders are "Key: Value"
// strings added to the request.
func Probe(ctx context.Context, dialer *network.Dialer, host, ip string, port int, timeout time.Duration, userAgent string, extraHeaders []string) models.HTTPProbeResult {
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

	ua := userAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	for _, h := range extraHeaders {
		// Skip malformed entries so one bad --header does not abort the probe.
		if k, v, ok := strings.Cut(h, ":"); ok && validHeaderName(strings.TrimSpace(k)) {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}

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

	// Read a bounded slice of the body for title and technology detection.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if title := extractTitle(body); title != "" {
		result.Title = &title
	}
	if tech := detectTech(resp.Header, body); len(tech) > 0 {
		result.Tech = tech
	}

	// Check security headers
	result.SecurityHeaders = checkSecurityHeaders(resp.Header)

	return result
}

// validHeaderName reports whether s is a valid HTTP header field name (a
// non-empty RFC 7230 token), so a malformed --header entry is skipped rather
// than aborting the whole request.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	const nameSpecialChars = "!#$%&'*+-.^_`|~"
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(nameSpecialChars, r):
		default:
			return false
		}
	}
	return true
}

// extractTitle returns the trimmed, collapsed contents of the first <title> tag.
func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := strings.TrimSpace(string(m[1]))
	title = strings.Join(strings.Fields(title), " ") // collapse whitespace/newlines
	if utf8.RuneCountInString(title) > 200 {
		title = string([]rune(title)[:200]) // truncate on a rune boundary
	}
	return title
}

// techSignature matches a technology by a response-header value or a body marker.
type techSignature struct {
	name   string
	header string // header name to inspect (empty means body only)
	needle string // case-insensitive substring to look for
	body   bool   // also look in the body
}

var techSignatures = []techSignature{
	{name: "WordPress", body: true, needle: "wp-content"},
	{name: "Drupal", header: "X-Generator", needle: "drupal"},
	{name: "Drupal", body: true, needle: "drupal-settings-json"},
	{name: "Joomla", body: true, needle: "/media/jui/"},
	{name: "Django", body: true, needle: "csrfmiddlewaretoken"},
	{name: "Laravel", header: "Set-Cookie", needle: "laravel_session"},
	{name: "Ruby on Rails", body: true, needle: "authenticity_token"},
	{name: "Ruby on Rails", header: "X-Runtime", needle: ""},
	{name: "Java", header: "Set-Cookie", needle: "jsessionid"},
	{name: "ASP.NET", header: "X-Powered-By", needle: "asp.net"},
	{name: "ASP.NET", header: "Set-Cookie", needle: "asp.net_sessionid"},
	{name: "PHP", header: "X-Powered-By", needle: "php"},
	{name: "Next.js", body: true, needle: "__next_data__"},
	{name: "Nuxt.js", body: true, needle: "__nuxt__"},
	{name: "React", body: true, needle: "data-reactroot"},
	{name: "Angular", body: true, needle: "ng-version"},
	{name: "Vue.js", body: true, needle: "data-v-app"},
	{name: "Cloudflare", header: "Server", needle: "cloudflare"},
	{name: "Cloudflare", header: "CF-RAY", needle: ""},
	{name: "Vercel", header: "Server", needle: "vercel"},
	{name: "Nginx", header: "Server", needle: "nginx"},
	{name: "Apache", header: "Server", needle: "apache"},
	{name: "Microsoft-IIS", header: "Server", needle: "microsoft-iis"},
	{name: "Caddy", header: "Server", needle: "caddy"},
	{name: "Envoy", header: "Server", needle: "envoy"},
	{name: "Kong", header: "Via", needle: "kong"},
	{name: "Amazon S3", header: "Server", needle: "amazons3"},
	{name: "Varnish", header: "Via", needle: "varnish"},
}

// detectTech applies the signature list to headers and body, returning a sorted,
// de-duplicated list of matched technologies.
func detectTech(h http.Header, body []byte) []string {
	lowerBody := strings.ToLower(string(body))
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, sig := range techSignatures {
		if sig.header != "" {
			// A present header with an empty needle is itself the signal.
			vals := h.Values(sig.header)
			if len(vals) > 0 && sig.needle == "" {
				add(sig.name)
				continue
			}
			for _, v := range vals {
				if sig.needle != "" && strings.Contains(strings.ToLower(v), sig.needle) {
					add(sig.name)
					break
				}
			}
		}
		if sig.body && sig.needle != "" && strings.Contains(lowerBody, sig.needle) {
			add(sig.name)
		}
	}
	return out
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
