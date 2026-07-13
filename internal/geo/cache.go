// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package geo

import (
	"bytes"
	"net"
	"strings"
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

	whois     map[string]models.WhoisResult
	whoisNets []whoisNet
	whoisMu   sync.RWMutex

	max int
}

// whoisNet caches a successful WHOIS result against the address range it
// describes so that other addresses in the same block reuse it instead of
// issuing a new query. This sharply reduces WHOIS traffic when scanning many
// hosts that share a netblock, which matters under the RIR rate limits. Ranges
// are stored as inclusive lo/hi bounds so both CIDR notation (ARIN CIDR) and
// dash-separated ranges (ARIN NetRange, RIPE/APNIC inetnum) are supported.
type whoisNet struct {
	lo     net.IP
	hi     net.IP
	result models.WhoisResult
}

// parseWhoisRange converts a WHOIS CIDR/range string into inclusive 16-byte
// bounds. It accepts CIDR notation ("192.0.2.0/24") and dash-separated ranges
// ("192.0.2.0 - 192.0.2.255"). ok is false when neither form parses.
func parseWhoisRange(s string) (lo, hi net.IP, ok bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil, false
		}
		hiBytes := make(net.IP, len(ipNet.IP))
		for i := range ipNet.IP {
			hiBytes[i] = ipNet.IP[i] | ^ipNet.Mask[i]
		}
		return ipNet.IP.To16(), hiBytes.To16(), true
	}
	// Dash-separated range. IPv4/IPv6 addresses never contain '-', so the first
	// '-' is the separator.
	if i := strings.Index(s, "-"); i >= 0 {
		a := net.ParseIP(strings.TrimSpace(s[:i]))
		b := net.ParseIP(strings.TrimSpace(s[i+1:]))
		if a != nil && b != nil {
			return a.To16(), b.To16(), true
		}
	}
	return nil, nil, false
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
	if v, ok := c.whois[ip]; ok {
		return v, ok
	}
	// Fall back to a netblock match from a prior lookup in the same range.
	if parsed := net.ParseIP(ip); parsed != nil {
		p16 := parsed.To16()
		for _, wn := range c.whoisNets {
			if bytes.Compare(wn.lo, p16) <= 0 && bytes.Compare(p16, wn.hi) <= 0 {
				return wn.result, true
			}
		}
	}
	return models.WhoisResult{}, false
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

	// Index the covering range so sibling addresses reuse this result.
	if result.Success && result.CIDR != nil {
		if lo, hi, ok := parseWhoisRange(*result.CIDR); ok {
			if len(c.whoisNets) >= c.max {
				c.whoisNets = c.whoisNets[1:]
			}
			c.whoisNets = append(c.whoisNets, whoisNet{lo: lo, hi: hi, result: result})
		}
	}
}
