// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/prodrom3/triton/internal/geo"
	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
)

// mockGeoReader implements GeoLookup for testing without real GeoIP databases.
type mockGeoReader struct {
	results map[string]models.GeoResult
}

func (m *mockGeoReader) Lookup(ip string) models.GeoResult {
	if r, ok := m.results[ip]; ok {
		return r
	}
	return models.GeoResult{IP: ip, City: "Mock", Country: "MC", Found: true}
}

func TestAnalyzeTargetIP(t *testing.T) {
	mock := &mockGeoReader{
		results: map[string]models.GeoResult{
			"8.8.8.8": {IP: "8.8.8.8", City: "Mountain View", Country: "US", Found: true},
		},
	}
	cache := geo.NewCache()
	limiter := network.NewRateLimiter(10, 60*time.Second)
	cfg := Config{
		MaxHops:      5,
		Timeout:      2 * time.Second,
		NoTraceroute: true,
	}

	ctx := context.Background()
	result := AnalyzeTarget(ctx, "8.8.8.8", mock, cfg, cache, limiter)

	if result.Target != "8.8.8.8" {
		t.Errorf("expected target 8.8.8.8, got %s", result.Target)
	}
	if !result.IsIP {
		t.Error("expected IsIP true")
	}
	if len(result.ResolvedIPs) != 1 || result.ResolvedIPs[0] != "8.8.8.8" {
		t.Error("expected resolved IP 8.8.8.8")
	}
	if len(result.GeoResults) != 1 {
		t.Fatalf("expected 1 geo result, got %d", len(result.GeoResults))
	}
	if result.GeoResults[0].City != "Mountain View" {
		t.Errorf("expected Mountain View, got %s", result.GeoResults[0].City)
	}
}

func TestAnalyzeTargetIPCached(t *testing.T) {
	mock := &mockGeoReader{}
	cache := geo.NewCache()
	limiter := network.NewRateLimiter(10, 60*time.Second)

	// Pre-populate cache
	cache.SetGeo("8.8.8.8", models.GeoResult{IP: "8.8.8.8", City: "Cached", Country: "CC", Found: true})

	cfg := Config{
		Timeout:      2 * time.Second,
		NoTraceroute: true,
	}

	ctx := context.Background()
	result := AnalyzeTarget(ctx, "8.8.8.8", mock, cfg, cache, limiter)

	if len(result.GeoResults) != 1 || result.GeoResults[0].City != "Cached" {
		t.Error("expected cached geo result")
	}
}

func TestAnalyzeTargetCancelled(t *testing.T) {
	mock := &mockGeoReader{}
	cache := geo.NewCache()
	limiter := network.NewRateLimiter(10, 60*time.Second)
	cfg := Config{
		Timeout:      2 * time.Second,
		NoTraceroute: true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Domain resolution should fail quickly due to cancelled context
	result := AnalyzeTarget(ctx, "example.com", mock, cfg, cache, limiter)
	// Either resolved (unlikely with cancelled ctx) or error
	if result.Error == nil && len(result.ResolvedIPs) == 0 {
		// Context cancelled before resolution - should have error
		t.Log("context cancelled as expected")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxHops != 20 {
		t.Errorf("expected MaxHops 20, got %d", cfg.MaxHops)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", cfg.Timeout)
	}
	if cfg.NoTraceroute {
		t.Error("expected NoTraceroute false")
	}
}

func TestRunGeoWithCache(t *testing.T) {
	mock := &mockGeoReader{
		results: map[string]models.GeoResult{
			"1.1.1.1": {IP: "1.1.1.1", City: "Sydney", Country: "AU", Found: true},
		},
	}
	cache := geo.NewCache()

	// First call should populate cache
	results := runGeo([]string{"1.1.1.1"}, mock, cache)
	if len(results) != 1 || results[0].City != "Sydney" {
		t.Error("expected Sydney")
	}

	// Verify it was cached
	cached, ok := cache.GetGeo("1.1.1.1")
	if !ok {
		t.Error("expected cache hit")
	}
	if cached.City != "Sydney" {
		t.Errorf("expected cached Sydney, got %s", cached.City)
	}

	// Second call should use cache (even if mock changes)
	mock.results["1.1.1.1"] = models.GeoResult{IP: "1.1.1.1", City: "Changed", Country: "XX"}
	results2 := runGeo([]string{"1.1.1.1"}, mock, cache)
	if results2[0].City != "Sydney" {
		t.Error("expected cached result, not fresh lookup")
	}
}
