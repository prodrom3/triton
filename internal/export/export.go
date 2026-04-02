// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/prodrom3/triton/internal/models"
)

// ExportCSV exports results to a CSV file.
func ExportCSV(results []models.AnalysisResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write BOM for UTF-8
	_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(f)

	header := []string{
		"target", "is_ip", "error", "resolved_ips",
		"ip", "city", "country", "region", "latitude", "longitude", "asn", "asn_org",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		base := []string{
			r.Target,
			fmt.Sprintf("%t", r.IsIP),
			derefStr(r.Error),
			strings.Join(r.ResolvedIPs, "; "),
		}

		if len(r.GeoResults) > 0 {
			for _, g := range r.GeoResults {
				row := make([]string, len(base))
				copy(row, base)
				row = append(row,
					g.IP,
					g.City,
					g.Country,
					derefStr(g.Region),
					fmtOptFloat(g.Latitude),
					fmtOptFloat(g.Longitude),
					fmtOptInt(g.ASN),
					derefStr(g.ASNOrg),
				)
				if err := w.Write(row); err != nil {
					return err
				}
			}
		} else {
			row := append(base, "", "", "", "", "", "", "", "")
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}

	w.Flush()
	return w.Error()
}

// esc escapes a string for safe HTML output.
func esc(s string) string {
	return html.EscapeString(s)
}

// ExportHTML exports results to a self-contained HTML report.
func ExportHTML(results []models.AnalysisResult, path string) error {
	htmlStr := buildHTML(results)
	return os.WriteFile(path, []byte(htmlStr), 0644)
}

func buildHTML(results []models.AnalysisResult) string {
	var rows strings.Builder
	for _, r := range results {
		ips := "-"
		if len(r.ResolvedIPs) > 0 {
			ips = esc(strings.Join(r.ResolvedIPs, ", "))
		}

		var geoParts []string
		for _, g := range r.GeoResults {
			loc := fmt.Sprintf("%s, %s", esc(g.City), esc(g.Country))
			if g.ASN != nil {
				loc += fmt.Sprintf(" (AS%d)", *g.ASN)
			}
			geoParts = append(geoParts, loc)
		}
		geoStr := "-"
		if len(geoParts) > 0 {
			geoStr = strings.Join(geoParts, "<br>")
		}

		traceStr := "-"
		if r.Traceroute != nil && r.Traceroute.Success {
			traceStr = fmt.Sprintf("%d hops", len(r.Traceroute.Hops))
		} else if r.Traceroute != nil && r.Traceroute.Error != nil {
			traceStr = esc(*r.Traceroute.Error)
		}

		portsStr := "-"
		if len(r.Ports) > 0 {
			var openPorts []string
			for _, p := range r.Ports {
				if p.Open {
					openPorts = append(openPorts, fmt.Sprintf("%d/%s", p.Port, esc(p.Service)))
				}
			}
			if len(openPorts) > 0 {
				portsStr = strings.Join(openPorts, ", ")
			} else {
				portsStr = "None open"
			}
		}

		tlsStr := "-"
		if r.TLS != nil && r.TLS.Success {
			if r.TLS.SelfSigned {
				tlsStr = "Self-signed"
			} else if r.TLS.Issuer != nil {
				tlsStr = esc(*r.TLS.Issuer)
			} else {
				tlsStr = "Valid"
			}
		}

		errorStr := ""
		if r.Error != nil {
			errorStr = esc(*r.Error)
		}

		fmt.Fprintf(&rows, `<tr>
            <td>%s</td><td>%s</td><td>%s</td>
            <td>%s</td><td>%s</td><td>%s</td>
            <td>%s</td>
        </tr>
`, esc(r.Target), ips, geoStr, traceStr, portsStr, tlsStr, errorStr)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>triton Report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2em; background: #f5f5f5; }
h1 { color: #2c3e50; }
table { border-collapse: collapse; width: 100%%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
th { background: #2c3e50; color: white; padding: 10px; text-align: left; }
td { padding: 8px 10px; border-bottom: 1px solid #eee; }
tr:hover { background: #f0f7ff; }
</style></head><body>
<h1>triton Report</h1>
<p>%d target(s) analyzed</p>
<table>
<tr><th>Target</th><th>IPs</th><th>Geolocation</th><th>Traceroute</th><th>Ports</th><th>TLS</th><th>Error</th></tr>
%s
</table></body></html>`, len(results), rows.String())
}

// ExportMap exports a geo map as a self-contained HTML file with Leaflet.
// Marker data is passed as JSON, which handles escaping for JavaScript contexts.
func ExportMap(results []models.AnalysisResult, path string) error {
	type marker struct {
		Lat   float64 `json:"lat"`
		Lon   float64 `json:"lon"`
		Label string  `json:"label"`
		IP    string  `json:"ip"`
	}

	var markers []marker
	for _, r := range results {
		for _, g := range r.GeoResults {
			if g.Latitude != nil && g.Longitude != nil {
				markers = append(markers, marker{
					Lat:   *g.Latitude,
					Lon:   *g.Longitude,
					Label: fmt.Sprintf("%s - %s, %s", r.Target, g.City, g.Country),
					IP:    g.IP,
				})
			}
		}
	}

	markersJSON, err := json.Marshal(markers)
	if err != nil {
		markersJSON = []byte("[]")
	}

	// Uses textContent for popup rendering to prevent XSS.
	// Variable named 'leafletMap' to avoid shadowing the JS Map built-in.
	htmlStr := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>triton Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>body{margin:0}#map{height:100vh;width:100vw}</style>
</head><body>
<div id="map"></div>
<script>
var leafletMap = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: 'OpenStreetMap'
}).addTo(leafletMap);
var markers = %s;
markers.forEach(function(m) {
    var el = document.createElement('div');
    var b = document.createElement('b');
    b.textContent = m.label;
    el.appendChild(b);
    el.appendChild(document.createElement('br'));
    el.appendChild(document.createTextNode(m.ip));
    L.marker([m.lat, m.lon]).addTo(leafletMap).bindPopup(el);
});
if (markers.length > 0) {
    var bounds = markers.map(function(m) { return [m.lat, m.lon]; });
    leafletMap.fitBounds(bounds, {padding: [50, 50]});
}
</script></body></html>`, string(markersJSON))

	return os.WriteFile(path, []byte(htmlStr), 0644)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func fmtOptFloat(f *float64) string {
	if f == nil {
		return ""
	}
	return fmt.Sprintf("%g", *f)
}

func fmtOptInt(i *int) string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%d", *i)
}
