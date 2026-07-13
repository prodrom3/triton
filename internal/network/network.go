// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"context"
	"net"
)

// ValidateIP checks if a string is a valid IPv4 or IPv6 address.
func ValidateIP(address string) bool {
	return net.ParseIP(address) != nil
}

// cgnatNet is the carrier-grade NAT range 100.64.0.0/10 (RFC 6598).
var cgnatNet = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// IsPrivate reports whether ip is a non-public address: loopback, private
// (RFC1918 / ULA), link-local, unspecified, multicast, carrier-grade NAT
// (100.64.0.0/10), the "this network" block (0.0.0.0/8), or the limited
// broadcast address. This covers the ranges that matter for SSRF protection,
// including the cloud metadata endpoint 169.254.169.254 (link-local). A string
// that is not a valid IP returns false.
func IsPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() ||
		parsed.IsPrivate() ||
		parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() ||
		parsed.IsUnspecified() ||
		parsed.IsMulticast() ||
		cgnatNet.Contains(parsed) {
		return true
	}
	if v4 := parsed.To4(); v4 != nil {
		// 0.0.0.0/8 "this network" and the 255.255.255.255 limited broadcast.
		if v4[0] == 0 {
			return true
		}
		if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
			return true
		}
	}
	return false
}

// IsIPv4 reports whether address is a valid IPv4 address.
func IsIPv4(address string) bool {
	parsed := net.ParseIP(address)
	return parsed != nil && parsed.To4() != nil
}

// FilterByFamily keeps only addresses of the requested IP family: 4 for IPv4,
// 6 for IPv6, and 0 (or any other value) for no filtering.
func FilterByFamily(ips []string, family int) []string {
	if family != 4 && family != 6 {
		return ips
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		isV4 := parsed.To4() != nil
		if (family == 4 && isV4) || (family == 6 && !isV4) {
			out = append(out, ip)
		}
	}
	return out
}

// ResolveDomain resolves a domain name to its IP addresses.
// The provided context controls cancellation and timeout.
func ResolveDomain(ctx context.Context, domain string) []string {
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool, len(addrs))
	unique := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if !seen[addr] {
			seen[addr] = true
			unique = append(unique, addr)
		}
	}
	return unique
}

// ReverseDNS performs a reverse DNS lookup on an IP address.
// The provided context controls cancellation and timeout.
func ReverseDNS(ctx context.Context, ip string) *string {
	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil
	}
	hostname := names[0]
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	if hostname == ip {
		return nil
	}
	return &hostname
}
