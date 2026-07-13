// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package diff

import "testing"

// FuzzParsePrevious ensures the previous-scan JSON parser and the diff engine
// never panic on arbitrary input, since the diff file is attacker-influenceable.
func FuzzParsePrevious(f *testing.F) {
	f.Add([]byte(`[{"target":"a","ports":[80]}]`))
	f.Add([]byte(`{"results":[{"target":"b"}]}`))
	f.Add([]byte(`{"target":"c","tls":{"self_signed":true}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`{"results":"notarray"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		prev, err := parsePrevious(data)
		if err != nil {
			return
		}
		// Feed the parsed data back through the diff engine both ways.
		current := []map[string]any{}
		for _, m := range prev {
			current = append(current, m)
		}
		_ = DiffResults(current, prev)
		_ = DiffResults(nil, prev)
	})
}
