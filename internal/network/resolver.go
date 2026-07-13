// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package network

import (
	"context"
	"net"
	"strings"
	"time"
)

// NewResolver builds a *net.Resolver that sends queries to the given DNS server
// (host or host:port; port 53 is assumed when omitted). An empty server returns
// the system default resolver.
func NewResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	addr := normalizeResolverAddr(server)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// normalizeResolverAddr turns a resolver value into host:port, defaulting to
// port 53. It handles a bare host or IP, a bracketed IPv6 literal with or
// without a port, and a value with a trailing colon (empty port).
func normalizeResolverAddr(server string) string {
	if host, port, err := net.SplitHostPort(server); err == nil {
		if port == "" {
			return net.JoinHostPort(host, "53")
		}
		return server
	}
	return net.JoinHostPort(strings.Trim(server, "[]"), "53")
}

// OrDefaultResolver returns r, or the system resolver when r is nil, so callers
// can accept a nil resolver safely.
func OrDefaultResolver(r *net.Resolver) *net.Resolver {
	if r != nil {
		return r
	}
	return net.DefaultResolver
}
