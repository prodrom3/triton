// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prodrom3/triton/internal/models"
)

var whoisServers = map[string]string{
	"arin":    "whois.arin.net",
	"ripe":    "whois.ripe.net",
	"apnic":   "whois.apnic.net",
	"lacnic":  "whois.lacnic.net",
	"afrinic": "whois.afrinic.net",
}

var allowedWhoisServers map[string]bool

func init() {
	allowedWhoisServers = make(map[string]bool)
	for _, s := range whoisServers {
		allowedWhoisServers[s] = true
	}
}

var (
	referralPattern = regexp.MustCompile(`(?i)(?:ReferralServer|refer):\s*(?:whois://)?(\S+)`)

	fieldPatterns = map[string]*regexp.Regexp{
		"netname":     regexp.MustCompile(`(?i)(?:NetName|netname):\s*(.+)`),
		"org":         regexp.MustCompile(`(?i)(?:OrgName|org-name|Organisation|organization|org):\s*(.+)`),
		"cidr":        regexp.MustCompile(`(?i)(?:CIDR|inetnum|inet6num|NetRange):\s*(.+)`),
		"description": regexp.MustCompile(`(?i)(?:OrgTechName|descr|Comment):\s*(.+)`),
	}

	sanitizeRe = regexp.MustCompile(`[\r\n\x00-\x1f\x7f]`)

	whoisMaxRespBytes = 64 * 1024
)

func sanitizeWhoisQuery(query string) string {
	return strings.TrimSpace(sanitizeRe.ReplaceAllString(query, ""))
}

// RateLimiter enforces a sliding-window rate limit.
type RateLimiter struct {
	mu         sync.Mutex
	timestamps []time.Time
	maxQueries int
	window     time.Duration
}

// NewRateLimiter creates a rate limiter with the given max queries per window.
func NewRateLimiter(maxQueries int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		maxQueries: maxQueries,
		window:     window,
	}
}

// Allow returns true if the request is within the rate limit.
func (rl *RateLimiter) Allow() bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := now.Add(-rl.window)
	start := 0
	for start < len(rl.timestamps) && rl.timestamps[start].Before(cutoff) {
		start++
	}
	rl.timestamps = rl.timestamps[start:]

	if len(rl.timestamps) >= rl.maxQueries {
		return false
	}
	rl.timestamps = append(rl.timestamps, now)
	return true
}

// Reset clears all tracked timestamps (useful for testing).
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.timestamps = nil
}

func whoisQuery(ctx context.Context, server, query string, timeout time.Duration) (string, error) {
	safe := sanitizeWhoisQuery(query)

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(safe + "\r\n"))
	if err != nil {
		return "", err
	}

	var buf []byte
	tmp := make([]byte, 4096)
	for len(buf) < whoisMaxRespBytes {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	return string(buf), nil
}

// WhoisLookup performs a WHOIS lookup for an IP address with rate limiting.
// The provided context controls cancellation; the rate limiter controls throughput.
func WhoisLookup(ctx context.Context, ip string, timeout time.Duration, limiter *RateLimiter) models.WhoisResult {
	if !limiter.Allow() {
		return models.WhoisResult{
			IP:      ip,
			Success: false,
			Error:   models.Ptr("WHOIS rate limit exceeded (max 10 queries per 60 seconds)"),
		}
	}

	raw, err := whoisQuery(ctx, whoisServers["arin"], "n "+ip, timeout)
	if err != nil {
		return models.WhoisResult{
			IP:      ip,
			Success: false,
			Error:   models.Ptr(fmt.Sprintf("WHOIS lookup failed: %v", err)),
		}
	}

	if match := referralPattern.FindStringSubmatch(raw); match != nil {
		referralServer := strings.ToLower(strings.Split(match[1], ":")[0])
		if allowedWhoisServers[referralServer] && limiter.Allow() {
			if referred, err := whoisQuery(ctx, referralServer, ip, timeout); err == nil {
				raw = referred
			}
		}
	}

	fields := make(map[string]*string)
	for name, pattern := range fieldPatterns {
		if match := pattern.FindStringSubmatch(raw); match != nil {
			val := strings.TrimSpace(match[1])
			fields[name] = &val
		}
	}

	return models.WhoisResult{
		IP:          ip,
		Success:     true,
		Netname:     fields["netname"],
		Org:         fields["org"],
		CIDR:        fields["cidr"],
		Description: fields["description"],
	}
}
