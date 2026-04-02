// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPreviousSingle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	data := `{"target": "8.8.8.8", "is_ip": true, "resolved_ips": ["8.8.8.8"]}`
	os.WriteFile(path, []byte(data), 0644)

	prev, err := LoadPrevious(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prev["8.8.8.8"]; !ok {
		t.Error("expected 8.8.8.8 in results")
	}
}

func TestLoadPreviousBareArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "array.json")
	data := `[{"target": "8.8.8.8", "is_ip": true}, {"target": "1.1.1.1", "is_ip": true}]`
	os.WriteFile(path, []byte(data), 0644)

	prev, err := LoadPrevious(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 2 {
		t.Errorf("expected 2 results from bare array, got %d", len(prev))
	}
	if _, ok := prev["8.8.8.8"]; !ok {
		t.Error("expected 8.8.8.8 in results")
	}
}

func TestLoadPreviousMultiple(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	data := `{"results": [{"target": "8.8.8.8", "is_ip": true}, {"target": "1.1.1.1", "is_ip": true}]}`
	os.WriteFile(path, []byte(data), 0644)

	prev, err := LoadPrevious(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 2 {
		t.Errorf("expected 2 results, got %d", len(prev))
	}
}

func TestDiffResultsNewTarget(t *testing.T) {
	current := []map[string]any{
		{"target": "8.8.8.8", "is_ip": true},
		{"target": "1.1.1.1", "is_ip": true},
	}
	previous := map[string]map[string]any{
		"8.8.8.8": {"target": "8.8.8.8", "is_ip": true},
	}

	changes := DiffResults(current, previous)
	found := false
	for _, c := range changes {
		if c["target"] == "1.1.1.1" && c["change"] == "new" {
			found = true
		}
	}
	if !found {
		t.Error("expected new target 1.1.1.1")
	}
}

func TestDiffResultsRemovedTarget(t *testing.T) {
	current := []map[string]any{
		{"target": "8.8.8.8", "is_ip": true},
	}
	previous := map[string]map[string]any{
		"8.8.8.8": {"target": "8.8.8.8", "is_ip": true},
		"1.1.1.1": {"target": "1.1.1.1", "is_ip": true},
	}

	changes := DiffResults(current, previous)
	found := false
	for _, c := range changes {
		if c["target"] == "1.1.1.1" && c["change"] == "removed" {
			found = true
		}
	}
	if !found {
		t.Error("expected removed target 1.1.1.1")
	}
}

func TestDiffResultsChanged(t *testing.T) {
	current := []map[string]any{
		{"target": "8.8.8.8", "is_ip": true, "resolved_ips": []string{"8.8.8.8"}},
	}
	previous := map[string]map[string]any{
		"8.8.8.8": {"target": "8.8.8.8", "is_ip": true, "resolved_ips": []string{"8.8.4.4"}},
	}

	changes := DiffResults(current, previous)
	if len(changes) == 0 {
		t.Error("expected changes")
	}
}

func TestDiffResultsNoChanges(t *testing.T) {
	data := map[string]any{"target": "8.8.8.8", "is_ip": true}
	current := []map[string]any{data}
	previous := map[string]map[string]any{"8.8.8.8": data}

	changes := DiffResults(current, previous)
	if len(changes) != 0 {
		t.Errorf("expected no changes, got %d", len(changes))
	}
}

func TestSummarize(t *testing.T) {
	// Short list
	got := summarize([]any{"a", "b"})
	if got != `["a","b"]` {
		t.Errorf("unexpected: %s", got)
	}

	// Long list
	long := make([]any, 10)
	for i := range long {
		long[i] = i
	}
	got = summarize(long)
	if got != "[10 items]" {
		t.Errorf("expected [10 items], got %s", got)
	}

	// Map
	m := map[string]any{"key": "value"}
	got = summarize(m)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Errorf("expected valid JSON, got %s", got)
	}

	// String
	got = summarize("hello")
	if got != "hello" {
		t.Errorf("expected hello, got %s", got)
	}
}
