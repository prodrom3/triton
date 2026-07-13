// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html"
	"html/template"
	"os"
	"strings"

	"github.com/prodrom3/triton/internal/models"
)

// mapMarker is one point plotted on the geo map. Field names are exported so
// html/template can serialize them; the json tags name the JavaScript fields.
type mapMarker struct {
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
	Label string  `json:"label"`
	IP    string  `json:"ip"`
}

// mapPageTemplate renders the geo map. It uses html/template so the marker data
// is contextually auto-escaped for the <script> JavaScript context: values are
// serialized as JSON with < > & and the U+2028/U+2029 line terminators escaped,
// which makes it impossible for an attacker-controlled target name or WHOIS
// field to break out of the script and inject markup or code.
var mapPageTemplate = template.Must(template.New("map").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>triton Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
    integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="anonymous"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
    integrity="sha256-20nQCchB9co0qIjJ8T7CfaFXCwcJ0T6EOtvsyh8fNbQ=" crossorigin="anonymous"></script>
<style>body{margin:0}#map{height:100vh;width:100vw}</style>
</head><body>
<div id="map"></div>
<script>
var leafletMap = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: 'OpenStreetMap'
}).addTo(leafletMap);
var markers = {{ .Markers }};
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
</script></body></html>`))

// stripControl removes control characters (C0, DEL, C1) from untrusted strings
// so exported files cannot carry terminal escape sequences.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// csvSafe neutralizes CSV formula injection. Spreadsheet applications treat a
// cell beginning with '=', '+', '-', '@', or a control character as a formula;
// prefixing such values with a single quote forces them to be read as text.
func csvSafe(s string) string {
	s = stripControl(s)
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

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
			csvSafe(r.Target),
			fmt.Sprintf("%t", r.IsIP),
			csvSafe(derefStr(r.Error)),
			csvSafe(strings.Join(r.ResolvedIPs, "; ")),
		}

		if len(r.GeoResults) > 0 {
			for _, g := range r.GeoResults {
				row := make([]string, len(base))
				copy(row, base)
				row = append(row,
					csvSafe(g.IP),
					csvSafe(g.City),
					csvSafe(g.Country),
					csvSafe(derefStr(g.Region)),
					fmtOptFloat(g.Latitude),
					fmtOptFloat(g.Longitude),
					fmtOptInt(g.ASN),
					csvSafe(derefStr(g.ASNOrg)),
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

// esc escapes a string for safe HTML output, first removing control characters.
func esc(s string) string {
	return html.EscapeString(stripControl(s))
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

// ExportMap exports a geo map as a single HTML file. Marker data is embedded as
// JSON (which handles JavaScript-context escaping) and rendered with textContent
// only. The Leaflet library and map tiles load from public CDNs over TLS; the
// library assets are pinned by version and guarded with Subresource Integrity
// hashes, so a tampered CDN response is rejected by the browser. Viewing the map
// therefore requires network access.
func ExportMap(results []models.AnalysisResult, path string) error {
	var markers []mapMarker
	for _, r := range results {
		for _, g := range r.GeoResults {
			if g.Latitude != nil && g.Longitude != nil {
				markers = append(markers, mapMarker{
					Lat:   *g.Latitude,
					Lon:   *g.Longitude,
					Label: fmt.Sprintf("%s - %s, %s", r.Target, g.City, g.Country),
					IP:    g.IP,
				})
			}
		}
	}

	var buf bytes.Buffer
	if err := mapPageTemplate.Execute(&buf, struct{ Markers []mapMarker }{Markers: markers}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
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
