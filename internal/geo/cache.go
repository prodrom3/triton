// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package geo

import (
	"sync"

	"github.com/prodrom3/triton/internal/models"
)

const defaultMaxCacheSize = 10_000

// Cache is a thread-safe cache for geo, traceroute, and WHOIS results.
// Each map has its own RWMutex to minimize contention across independent lookups.
type Cache struct {
	geo   map[string]models.GeoResult
	geoMu sync.RWMutex

	trace   map[string]models.TracerouteResult
	traceMu sync.RWMutex

	whois   map[string]models.WhoisResult
	whoisMu sync.RWMutex

	max int
}

// NewCache creates a new result cache with the default max size.
func NewCache() *Cache {
	return &Cache{
		geo:   make(map[string]models.GeoResult),
		trace: make(map[string]models.TracerouteResult),
		whois: make(map[string]models.WhoisResult),
		max:   defaultMaxCacheSize,
	}
}

func (c *Cache) GetGeo(ip string) (models.GeoResult, bool) {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	v, ok := c.geo[ip]
	return v, ok
}

func (c *Cache) SetGeo(ip string, result models.GeoResult) {
	c.geoMu.Lock()
	defer c.geoMu.Unlock()
	if len(c.geo) >= c.max {
		// Drop any one entry (fast eviction)
		for k := range c.geo {
			delete(c.geo, k)
			break
		}
	}
	c.geo[ip] = result
}

func (c *Cache) GetTrace(ip string) (models.TracerouteResult, bool) {
	c.traceMu.RLock()
	defer c.traceMu.RUnlock()
	v, ok := c.trace[ip]
	return v, ok
}

func (c *Cache) SetTrace(ip string, result models.TracerouteResult) {
	c.traceMu.Lock()
	defer c.traceMu.Unlock()
	if len(c.trace) >= c.max {
		for k := range c.trace {
			delete(c.trace, k)
			break
		}
	}
	c.trace[ip] = result
}

func (c *Cache) GetWhois(ip string) (models.WhoisResult, bool) {
	c.whoisMu.RLock()
	defer c.whoisMu.RUnlock()
	v, ok := c.whois[ip]
	return v, ok
}

func (c *Cache) SetWhois(ip string, result models.WhoisResult) {
	c.whoisMu.Lock()
	defer c.whoisMu.Unlock()
	if len(c.whois) >= c.max {
		for k := range c.whois {
			delete(c.whois, k)
			break
		}
	}
	c.whois[ip] = result
}
