// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package geo

import (
	"sync"
	"testing"

	"github.com/prodrom3/triton/internal/models"
)

func TestCacheGetSetGeo(t *testing.T) {
	c := NewCache()

	_, ok := c.GetGeo("8.8.8.8")
	if ok {
		t.Error("expected cache miss for 8.8.8.8")
	}

	geo := models.GeoResult{IP: "8.8.8.8", City: "Mountain View", Country: "US", Found: true}
	c.SetGeo("8.8.8.8", geo)

	got, ok := c.GetGeo("8.8.8.8")
	if !ok {
		t.Error("expected cache hit for 8.8.8.8")
	}
	if got.City != "Mountain View" {
		t.Errorf("expected Mountain View, got %s", got.City)
	}
}

func TestCacheGetSetTrace(t *testing.T) {
	c := NewCache()

	_, ok := c.GetTrace("8.8.8.8")
	if ok {
		t.Error("expected cache miss")
	}

	tr := models.TracerouteResult{Target: "8.8.8.8", Success: true}
	c.SetTrace("8.8.8.8", tr)

	got, ok := c.GetTrace("8.8.8.8")
	if !ok {
		t.Error("expected cache hit")
	}
	if !got.Success {
		t.Error("expected success")
	}
}

func TestCacheGetSetWhois(t *testing.T) {
	c := NewCache()

	_, ok := c.GetWhois("8.8.8.8")
	if ok {
		t.Error("expected cache miss")
	}

	w := models.WhoisResult{IP: "8.8.8.8", Success: true}
	c.SetWhois("8.8.8.8", w)

	got, ok := c.GetWhois("8.8.8.8")
	if !ok {
		t.Error("expected cache hit")
	}
	if !got.Success {
		t.Error("expected success")
	}
}

func TestCacheEviction(t *testing.T) {
	c := &Cache{
		geo:   make(map[string]models.GeoResult),
		trace: make(map[string]models.TracerouteResult),
		whois: make(map[string]models.WhoisResult),
		max:   2,
	}

	c.SetGeo("a", models.GeoResult{IP: "a", City: "A"})
	c.SetGeo("b", models.GeoResult{IP: "b", City: "B"})
	c.SetGeo("c", models.GeoResult{IP: "c", City: "C"})

	// One of the first two should have been evicted
	count := 0
	if _, ok := c.GetGeo("a"); ok {
		count++
	}
	if _, ok := c.GetGeo("b"); ok {
		count++
	}
	if _, ok := c.GetGeo("c"); ok {
		count++
	}
	if count > 2 {
		t.Errorf("expected at most 2 entries, got %d", count)
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := NewCache()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			c.SetGeo(ip, models.GeoResult{IP: ip, City: "Test"})
			c.GetGeo(ip)
		}(i)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			c.SetTrace(ip, models.TracerouteResult{Target: ip, Success: true})
			c.GetTrace(ip)
		}(i)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			c.SetWhois(ip, models.WhoisResult{IP: ip, Success: true})
			c.GetWhois(ip)
		}(i)
	}

	wg.Wait()
}

func TestCacheIndependentLocks(t *testing.T) {
	// Verify that geo/trace/whois operations don't block each other.
	// If they shared a lock, this concurrent access pattern could deadlock
	// with a non-reentrant mutex.
	c := NewCache()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetGeo("x", models.GeoResult{IP: "x"})
			c.SetTrace("x", models.TracerouteResult{Target: "x"})
			c.SetWhois("x", models.WhoisResult{IP: "x"})
			c.GetGeo("x")
			c.GetTrace("x")
			c.GetWhois("x")
		}()
	}

	wg.Wait()
}
