// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package export

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prodrom3/triton/internal/models"
)

// TestMapExportEscapesScriptBreakout ensures attacker-controlled marker data
// cannot break out of the <script> block in the map export.
func TestMapExportEscapesScriptBreakout(t *testing.T) {
	lat, lon := 1.0, 2.0
	evil := "</script><script>alert(1)</script>'\"&<>\u2028\u2029"
	results := []models.AnalysisResult{{
		Target: evil,
		GeoResults: []models.GeoResult{{
			IP: evil, City: "City", Country: "US",
			Latitude: &lat, Longitude: &lon,
		}},
	}}

	path := filepath.Join(t.TempDir(), "m.html")
	if err := ExportMap(results, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)

	if strings.Contains(s, "</script><script>alert") {
		t.Errorf("script breakout not escaped:\n%s", s)
	}
	if strings.ContainsRune(s, '\u2028') || strings.ContainsRune(s, '\u2029') {
		t.Error("raw U+2028/U+2029 line terminator present in output")
	}
	if n := strings.Count(s, "</script>"); n != 2 {
		t.Errorf("unexpected </script> count %d (possible breakout or malformed)", n)
	}
}
