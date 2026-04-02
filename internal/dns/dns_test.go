// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package dns

import (
	"context"
	"testing"
	"time"
)

func TestQueryDnsRecordsReturnsStruct(t *testing.T) {
	// This test verifies the function signature and basic struct population.
	// With a short timeout, results may be empty but the function should not panic.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	records := QueryDnsRecords(ctx, "invalid.test.example")
	if records.Domain != "invalid.test.example" {
		t.Errorf("expected domain invalid.test.example, got %s", records.Domain)
	}
}

func TestQueryDnsRecordsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	records := QueryDnsRecords(ctx, "example.com")
	if records.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", records.Domain)
	}
	// With cancelled context, all lookups should fail gracefully
}
