// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// LoadPrevious loads a previous results JSON file, keyed by target.
func LoadPrevious(path string) (map[string]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try as a bare JSON array first: [{"target":"a"}, ...]
	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		out := make(map[string]map[string]any)
		for _, m := range arr {
			target, _ := m["target"].(string)
			out[target] = m
		}
		return out, nil
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if resultsList, ok := raw["results"].([]any); ok {
		out := make(map[string]map[string]any)
		for _, item := range resultsList {
			if m, ok := item.(map[string]any); ok {
				target, _ := m["target"].(string)
				out[target] = m
			}
		}
		return out, nil
	}

	// Single result
	target, _ := raw["target"].(string)
	return map[string]map[string]any{target: raw}, nil
}

// DiffResults compares current results against previous, returning a list of changes.
func DiffResults(current []map[string]any, previous map[string]map[string]any) []map[string]any {
	var changes []map[string]any

	currentTargets := make(map[string]bool)
	for _, r := range current {
		target, _ := r["target"].(string)
		currentTargets[target] = true
	}
	previousTargets := make(map[string]bool)
	for t := range previous {
		previousTargets[t] = true
	}

	// New targets
	for t := range currentTargets {
		if !previousTargets[t] {
			changes = append(changes, map[string]any{
				"target": t, "change": "new", "details": "New target added",
			})
		}
	}

	// Removed targets
	for t := range previousTargets {
		if !currentTargets[t] {
			changes = append(changes, map[string]any{
				"target": t, "change": "removed", "details": "Target no longer present",
			})
		}
	}

	// Changed targets
	for _, r := range current {
		target, _ := r["target"].(string)
		prev, ok := previous[target]
		if !ok {
			continue
		}
		changes = append(changes, diffDicts(prev, r, target)...)
	}

	return changes
}

func diffDicts(old, new map[string]any, target string) []map[string]any {
	var changes []map[string]any
	allKeys := make(map[string]bool)
	for k := range old {
		allKeys[k] = true
	}
	for k := range new {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		if key == "target" || key == "is_ip" {
			continue
		}
		oldVal, hasOld := old[key]
		newVal, hasNew := new[key]

		if !hasOld && hasNew {
			changes = append(changes, map[string]any{
				"target": target, "change": "added",
				"field": key, "value": summarize(newVal),
			})
		} else if hasOld && !hasNew {
			changes = append(changes, map[string]any{
				"target": target, "change": "removed",
				"field": key, "value": summarize(oldVal),
			})
		} else {
			oldJSON, _ := json.Marshal(oldVal)
			newJSON, _ := json.Marshal(newVal)
			if string(oldJSON) != string(newJSON) {
				changes = append(changes, map[string]any{
					"target": target, "change": "changed",
					"field": key,
					"old":   summarize(oldVal),
					"new":   summarize(newVal),
				})
			}
		}
	}

	return changes
}

func summarize(value any) string {
	switch v := value.(type) {
	case []any:
		if len(v) <= 3 {
			data, _ := json.Marshal(v)
			return string(data)
		}
		return fmt.Sprintf("[%d items]", len(v))
	case map[string]any:
		data, _ := json.Marshal(v)
		s := string(data)
		if len(s) > 80 {
			s = s[:80]
		}
		return s
	default:
		return fmt.Sprint(value)
	}
}
