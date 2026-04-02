// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prodrom3/triton/internal/dns"
	"github.com/prodrom3/triton/internal/geo"
	"github.com/prodrom3/triton/internal/httpprobe"
	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
	"github.com/prodrom3/triton/internal/ping"
	"github.com/prodrom3/triton/internal/scanner"
	"github.com/prodrom3/triton/internal/tracer"
)

// GeoLookup abstracts geolocation lookups for testability.
type GeoLookup interface {
	Lookup(ip string) models.GeoResult
}

// Config holds the analysis pipeline configuration.
type Config struct {
	MaxHops      int
	Timeout      time.Duration
	NoTraceroute bool
	AllIPs       bool
	DoWhois      bool
	DnsAll       bool
	DoPorts      bool
	PortList     []int
	DoTLS        bool
	DoHTTP       bool
	DoPing       bool
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		MaxHops: 20,
		Timeout: 30 * time.Second,
	}
}

// AnalyzeTarget runs all enabled probes on a target and returns the composite result.
// The provided context controls cancellation of all network operations.
func AnalyzeTarget(ctx context.Context, target string, geoReader GeoLookup, cfg Config, cache *geo.Cache, whoisLimiter *network.RateLimiter) models.AnalysisResult {
	isIP := network.ValidateIP(target)
	result := models.AnalysisResult{Target: target, IsIP: isIP}

	// Phase 1: DNS resolution
	var traceIP, scanIP string
	var geoIPs []string

	resolveCtx, resolveCancel := context.WithTimeout(ctx, cfg.Timeout)
	defer resolveCancel()

	if isIP {
		traceIP = target
		scanIP = target
		geoIPs = []string{target}
		result.ResolvedIPs = []string{target}
	} else {
		start := time.Now()
		ips := network.ResolveDomain(resolveCtx, target)
		slog.Info("Probe complete", "probe", "dns", "target", target, "duration", time.Since(start).Round(time.Millisecond))
		result.ResolvedIPs = ips
		if len(ips) == 0 {
			result.Error = models.Ptr("Could not resolve domain: " + target)
			slog.Warn("DNS resolution failed", "target", target)
			return result
		}
		traceIP = ips[0]
		scanIP = ips[0]
		if cfg.AllIPs {
			geoIPs = ips
		} else {
			geoIPs = ips[:1]
		}
	}

	slog.Info("Analyzing target", "target", target, "resolved", result.ResolvedIPs)

	// Phase 2: Geolocation (fast, local)
	result.GeoResults = runGeo(geoIPs, geoReader, cache)

	// Determine the hostname to send in HTTP Host headers.
	hostname := ""
	if !isIP {
		hostname = target
	}

	// Phase 3: Concurrent network probes
	var wg sync.WaitGroup
	var mu sync.Mutex

	if !cfg.NoTraceroute {
		if cached, ok := cache.GetTrace(traceIP); ok {
			result.Traceroute = &cached
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				tr := tracer.PerformTraceroute(ctx, traceIP, cfg.MaxHops, cfg.Timeout)
				slog.Info("Probe complete", "probe", "traceroute", "target", target, "duration", time.Since(start).Round(time.Millisecond))
				mu.Lock()
				result.Traceroute = &tr
				mu.Unlock()
				cache.SetTrace(traceIP, tr)
			}()
		}
	}

	if cfg.DoWhois {
		if cached, ok := cache.GetWhois(scanIP); ok {
			result.Whois = &cached
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				whoisTimeout := cfg.Timeout
				if whoisTimeout > 10*time.Second {
					whoisTimeout = 10 * time.Second
				}
				whoisCtx, cancel := context.WithTimeout(ctx, whoisTimeout)
				defer cancel()
				start := time.Now()
				w := network.WhoisLookup(whoisCtx, scanIP, whoisTimeout, whoisLimiter)
				slog.Info("Probe complete", "probe", "whois", "target", target, "duration", time.Since(start).Round(time.Millisecond))
				mu.Lock()
				result.Whois = &w
				mu.Unlock()
				cache.SetWhois(scanIP, w)
			}()
		}
	}

	if cfg.DnsAll && !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
			defer cancel()
			start := time.Now()
			dr := dns.QueryDnsRecords(dnsCtx, target)
			slog.Info("Probe complete", "probe", "dns_records", "target", target, "duration", time.Since(start).Round(time.Millisecond))
			mu.Lock()
			result.DnsRecords = &dr
			mu.Unlock()
		}()
	}

	if cfg.DoPorts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			portTimeout := cfg.Timeout
			if portTimeout > 3*time.Second {
				portTimeout = 3 * time.Second
			}
			start := time.Now()
			open, closedCount := scanner.ScanPorts(ctx, scanIP, cfg.PortList, portTimeout, true, 16, hostname)
			slog.Info("Probe complete", "probe", "ports", "target", target, "open", len(open), "closed", closedCount, "duration", time.Since(start).Round(time.Millisecond))
			mu.Lock()
			result.Ports = open
			result.ClosedPorts = closedCount
			mu.Unlock()
		}()
	}

	if cfg.DoTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tlsHost := target
			if isIP {
				tlsHost = scanIP
			}
			start := time.Now()
			t := scanner.TLSCertInfo(ctx, tlsHost, 443, cfg.Timeout)
			slog.Info("Probe complete", "probe", "tls", "target", target, "duration", time.Since(start).Round(time.Millisecond))
			mu.Lock()
			result.TLS = &t
			mu.Unlock()
		}()
	}

	if cfg.DoPing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			p := ping.TCPPing(ctx, scanIP, 80, 3, cfg.Timeout)
			slog.Info("Probe complete", "probe", "ping", "target", target, "duration", time.Since(start).Round(time.Millisecond))
			mu.Lock()
			result.Ping = &p
			mu.Unlock()
		}()
	}

	// Wait for all probes including port scan to finish before HTTP probing,
	// since HTTP probing depends on knowing which ports are open.
	wg.Wait()

	// Phase 4: HTTP probing on discovered open web ports
	if cfg.DoHTTP {
		httpHost := target
		if isIP {
			httpHost = scanIP
		}
		webPorts := findWebPorts(result.Ports)
		if len(webPorts) > 0 {
			var httpWg sync.WaitGroup
			var httpResults []models.HTTPProbeResult
			var httpMu sync.Mutex

			for _, port := range webPorts {
				httpWg.Add(1)
				go func(p int) {
					defer httpWg.Done()
					start := time.Now()
					hr := httpprobe.Probe(ctx, httpHost, scanIP, p, cfg.Timeout)
					slog.Info("Probe complete", "probe", "http", "target", target, "port", p, "status", hr.StatusCode, "duration", time.Since(start).Round(time.Millisecond))
					httpMu.Lock()
					httpResults = append(httpResults, hr)
					httpMu.Unlock()
				}(port)
			}
			httpWg.Wait()
			result.HTTP = httpResults
		}
	}

	slog.Info("Completed analysis", "target", target)
	return result
}

// findWebPorts returns HTTP-capable ports from the open port list.
func findWebPorts(ports []models.PortResult) []int {
	webServices := map[string]bool{
		"http": true, "https": true, "http-alt": true, "https-alt": true,
	}
	var result []int
	for _, p := range ports {
		if p.Open && webServices[p.Service] {
			result = append(result, p.Port)
		}
	}
	// If no ports were scanned but HTTP is requested, probe common ports
	if len(result) == 0 && len(ports) == 0 {
		return []int{80, 443}
	}
	return result
}

func runGeo(ips []string, reader GeoLookup, cache *geo.Cache) []models.GeoResult {
	var results []models.GeoResult
	for _, ip := range ips {
		if cached, ok := cache.GetGeo(ip); ok {
			results = append(results, cached)
		} else {
			g := reader.Lookup(ip)
			results = append(results, g)
			cache.SetGeo(ip, g)
		}
	}
	return results
}
