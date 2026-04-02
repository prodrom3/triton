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

func sampleResults() []models.AnalysisResult {
	lat, lon := 37.386, -122.084
	return []models.AnalysisResult{
		{
			Target:      "example.com",
			IsIP:        false,
			ResolvedIPs: []string{"93.184.216.34"},
			GeoResults: []models.GeoResult{
				{
					IP: "93.184.216.34", City: "Norwell", Country: "US",
					Found: true, Latitude: &lat, Longitude: &lon,
					ASN: models.Ptr(15133),
				},
			},
		},
	}
}

func TestExportCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.csv")

	err := ExportCSV(sampleResults(), path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "example.com") {
		t.Error("expected target in CSV")
	}
	if !strings.Contains(content, "Norwell") {
		t.Error("expected city in CSV")
	}
}

func TestExportCSVEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.csv")

	err := ExportCSV(nil, path)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExportHTML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")

	err := ExportHTML(sampleResults(), path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "triton Report") {
		t.Error("expected triton Report title")
	}
	if !strings.Contains(content, "example.com") {
		t.Error("expected target in HTML")
	}
}

func TestExportHTMLXSSEscaping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xss.html")

	results := []models.AnalysisResult{
		{
			Target:      "<script>alert(1)</script>",
			IsIP:        false,
			ResolvedIPs: []string{"1.2.3.4"},
			Error:       models.Ptr("<img onerror=alert(1)>"),
		},
	}

	err := ExportHTML(results, path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Raw script tags should not appear - they should be escaped
	if strings.Contains(content, "<script>alert") {
		t.Error("XSS: unescaped <script> tag found in HTML output")
	}
	if strings.Contains(content, "<img onerror") {
		t.Error("XSS: unescaped <img> tag found in HTML output")
	}
	// Escaped versions should be present
	if !strings.Contains(content, "&lt;script&gt;") {
		t.Error("expected escaped script tag")
	}
}

func TestExportMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.html")

	err := ExportMap(sampleResults(), path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "leaflet") {
		t.Error("expected Leaflet reference")
	}
	if !strings.Contains(content, "37.386") {
		t.Error("expected latitude in markers")
	}
	// Map should use textContent for safety
	if !strings.Contains(content, "textContent") {
		t.Error("expected textContent for XSS-safe popup rendering")
	}
	// Should use leafletMap, not reserved word 'map'
	if !strings.Contains(content, "leafletMap") {
		t.Error("expected leafletMap variable name (not reserved word 'map')")
	}
}

func TestExportMapNoMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty_map.html")

	results := []models.AnalysisResult{
		{Target: "bad.example", IsIP: false, Error: models.Ptr("failed")},
	}
	err := ExportMap(results, path)
	if err != nil {
		t.Fatal(err)
	}
}
