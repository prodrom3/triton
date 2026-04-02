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
