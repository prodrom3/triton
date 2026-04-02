// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package dns

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/prodrom3/triton/internal/models"
)

// QueryDnsRecords queries all DNS record types for a domain concurrently
// using Go's native DNS resolver.
func QueryDnsRecords(ctx context.Context, domain string) models.DnsRecords {
	records := models.DnsRecords{Domain: domain}
	resolver := net.DefaultResolver

	var wg sync.WaitGroup
	var mu sync.Mutex

	// NS - run first and share result with SOA to avoid duplicate queries
	var nsResults []string
	var nsOnce sync.Once

	lookupNS := func() {
		nss, err := resolver.LookupNS(ctx, domain)
		if err != nil || len(nss) == 0 {
			return
		}
		for _, ns := range nss {
			nsResults = append(nsResults, strings.TrimRight(ns.Host, "."))
		}
	}

	// NS
	wg.Add(1)
	go func() {
		defer wg.Done()
		nsOnce.Do(lookupNS)
		if len(nsResults) > 0 {
			mu.Lock()
			records.NS = nsResults
			mu.Unlock()
		}
	}()

	// SOA - reuses the NS lookup result.
	// Go stdlib lacks a direct SOA query, so the primary NS is used as
	// best-effort. This avoids a second LookupNS call.
	wg.Add(1)
	go func() {
		defer wg.Done()
		nsOnce.Do(lookupNS)
		if len(nsResults) > 0 {
			soa := nsResults[0]
			mu.Lock()
			records.SOA = &soa
			mu.Unlock()
		}
	}()

	// MX
	wg.Add(1)
	go func() {
		defer wg.Done()
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil || len(mxs) == 0 {
			return
		}
		var results []string
		for _, mx := range mxs {
			host := strings.TrimRight(mx.Host, ".")
			results = append(results, host)
		}
		mu.Lock()
		records.MX = results
		mu.Unlock()
	}()

	// TXT
	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := resolver.LookupTXT(ctx, domain)
		if err != nil || len(txts) == 0 {
			return
		}
		mu.Lock()
		records.TXT = txts
		mu.Unlock()
	}()

	// CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err != nil || cname == "" {
			return
		}
		cname = strings.TrimRight(cname, ".")
		if cname != domain {
			mu.Lock()
			records.CNAME = []string{cname}
			mu.Unlock()
		}
	}()

	wg.Wait()
	return records
}
