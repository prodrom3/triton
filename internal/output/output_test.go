// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prodrom3/triton/internal/models"
)

func testRenderer() (*Renderer, *bytes.Buffer, *bytes.Buffer) {
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	r := &Renderer{Out: outBuf, Err: errBuf, Quiet: false, outColor: false, errColor: false}
	return r, outBuf, errBuf
}

func TestFormatGeoFound(t *testing.T) {
	r, _, _ := testRenderer()
	lat, lon := 37.386, -122.084
	asn := 15169
	asnOrg := "Google LLC"
	g := models.GeoResult{
		IP: "8.8.8.8", City: "Mountain View", Country: "US",
		Found: true, Latitude: &lat, Longitude: &lon,
		ASN: &asn, ASNOrg: &asnOrg,
	}
	line := r.FormatGeo(g)
	if !strings.Contains(line, "8.8.8.8") {
		t.Error("expected IP in output")
	}
	if !strings.Contains(line, "Mountain View") {
		t.Error("expected city in output")
	}
	if !strings.Contains(line, "AS15169") {
		t.Error("expected ASN in output")
	}
}

func TestFormatGeoNotFound(t *testing.T) {
	r, _, _ := testRenderer()
	g := models.GeoResult{IP: "10.0.0.1", City: "N/A", Country: "N/A", Found: false}
	line := r.FormatGeo(g)
	if !strings.Contains(line, "10.0.0.1") {
		t.Error("expected IP in output")
	}
}

func TestFormatError(t *testing.T) {
	r, _, _ := testRenderer()
	line := r.FormatError("something went wrong")
	if !strings.Contains(line, "something went wrong") {
		t.Error("expected error message in output")
	}
}

func TestProgressQuiet(t *testing.T) {
	_, _, errBuf := testRenderer()
	r := &Renderer{Out: &bytes.Buffer{}, Err: errBuf, Quiet: true}
	r.Progress(1, 10, "8.8.8.8")
	if errBuf.Len() != 0 {
		t.Error("expected no progress output in quiet mode")
	}
}

func TestProgressNotQuiet(t *testing.T) {
	r, _, errBuf := testRenderer()
	r.Progress(1, 10, "8.8.8.8")
	if !strings.Contains(errBuf.String(), "8.8.8.8") {
		t.Error("expected target in progress output")
	}
}

func TestDNS(t *testing.T) {
	r, outBuf, _ := testRenderer()
	r.DNS("example.com", []string{"93.184.216.34"})
	if !strings.Contains(outBuf.String(), "example.com") {
		t.Error("expected domain in DNS output")
	}
	if !strings.Contains(outBuf.String(), "93.184.216.34") {
		t.Error("expected IP in DNS output")
	}
}

func TestDNSNoResults(t *testing.T) {
	r, outBuf, _ := testRenderer()
	r.DNS("bad.example", nil)
	if !strings.Contains(outBuf.String(), "No IPs found") {
		t.Error("expected no IPs message")
	}
}

func TestTracerouteOutput(t *testing.T) {
	r, outBuf, _ := testRenderer()
	rtt := 1.23
	hostname := "gw.local"
	tr := &models.TracerouteResult{
		Target: "8.8.8.8", Success: true,
		Hops: []models.TracerouteHop{
			{TTL: 1, IP: "192.168.1.1", RTT: &rtt, Hostname: &hostname},
		},
	}
	r.Traceroute(tr)
	output := outBuf.String()
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("expected hop IP")
	}
	if !strings.Contains(output, "gw.local") {
		t.Error("expected hostname")
	}
}

func TestTracerouteFailed(t *testing.T) {
	r, outBuf, _ := testRenderer()
	errMsg := "timed out"
	tr := &models.TracerouteResult{Target: "8.8.8.8", Success: false, Error: &errMsg}
	r.Traceroute(tr)
	if !strings.Contains(outBuf.String(), "timed out") {
		t.Error("expected error in output")
	}
}

func TestWhoisOutput(t *testing.T) {
	r, outBuf, _ := testRenderer()
	org := "Google LLC"
	netname := "GOOGLE"
	w := &models.WhoisResult{IP: "8.8.8.8", Success: true, Org: &org, Netname: &netname}
	r.Whois(w)
	output := outBuf.String()
	if !strings.Contains(output, "Google LLC") {
		t.Error("expected org in output")
	}
}

func TestPortsOutput(t *testing.T) {
	r, outBuf, _ := testRenderer()
	openPorts := []models.PortResult{
		{Port: 80, Open: true, Service: "http"},
		{Port: 443, Open: true, Service: "https"},
	}
	r.Ports(openPorts, 1)
	output := outBuf.String()
	if !strings.Contains(output, "80") {
		t.Error("expected port 80")
	}
	if !strings.Contains(output, "1 closed") {
		t.Error("expected closed port count")
	}
}

func TestPortsNoneOpen(t *testing.T) {
	r, outBuf, _ := testRenderer()
	r.Ports(nil, 5)
	if !strings.Contains(outBuf.String(), "No open ports") {
		t.Error("expected no open ports message")
	}
}

func TestTLSCertOutput(t *testing.T) {
	r, outBuf, _ := testRenderer()
	issuer := "Let's Encrypt"
	protocol := "TLSv1.3"
	tc := &models.TlsCertResult{
		Host: "example.com", Success: true,
		Issuer: &issuer, Protocol: &protocol,
	}
	r.TLSCert(tc)
	output := outBuf.String()
	if !strings.Contains(output, "Let's Encrypt") {
		t.Error("expected issuer")
	}
}

func TestTLSCertSelfSigned(t *testing.T) {
	r, outBuf, _ := testRenderer()
	tc := &models.TlsCertResult{Host: "test.local", Success: true, SelfSigned: true}
	r.TLSCert(tc)
	if !strings.Contains(outBuf.String(), "Self-signed") {
		t.Error("expected self-signed warning")
	}
}

func TestAnalysisIPTarget(t *testing.T) {
	r, outBuf, _ := testRenderer()
	result := models.AnalysisResult{
		Target: "8.8.8.8", IsIP: true,
		ResolvedIPs: []string{"8.8.8.8"},
		GeoResults: []models.GeoResult{
			{IP: "8.8.8.8", City: "Mountain View", Country: "US", Found: true},
		},
	}
	r.Analysis(result, false)
	output := outBuf.String()
	if !strings.Contains(output, "8.8.8.8") {
		t.Error("expected IP in output")
	}
	if strings.Contains(output, "DNS Resolution") {
		t.Error("IP target should not show DNS Resolution")
	}
}

func TestAnalysisDomainTarget(t *testing.T) {
	r, outBuf, _ := testRenderer()
	result := models.AnalysisResult{
		Target:      "example.com",
		IsIP:        false,
		ResolvedIPs: []string{"93.184.216.34"},
	}
	r.Analysis(result, false)
	output := outBuf.String()
	if !strings.Contains(output, "DNS Resolution") {
		t.Error("domain target should show DNS Resolution")
	}
}

func TestAnalysisWithError(t *testing.T) {
	r, outBuf, _ := testRenderer()
	result := models.AnalysisResult{
		Target: "bad.example", IsIP: false,
		Error: models.Ptr("Could not resolve domain"),
	}
	r.Analysis(result, false)
	if !strings.Contains(outBuf.String(), "Could not resolve domain") {
		t.Error("expected error in output")
	}
}

func TestJSONOutput(t *testing.T) {
	r, outBuf, _ := testRenderer()
	results := []models.AnalysisResult{
		{Target: "8.8.8.8", IsIP: true, ResolvedIPs: []string{"8.8.8.8"}},
	}
	r.JSONOutput(results)
	if !strings.Contains(outBuf.String(), `"target"`) {
		t.Error("expected JSON output")
	}
}

func TestDBWarning(t *testing.T) {
	r, outBuf, _ := testRenderer()
	r.DBWarning()
	output := outBuf.String()
	if !strings.Contains(output, "No GeoLite2 database found") {
		t.Error("expected DB warning")
	}
}

func TestDiffChanges(t *testing.T) {
	r, outBuf, _ := testRenderer()
	changes := []map[string]any{
		{"target": "8.8.8.8", "change": "new", "details": "New target added"},
		{"target": "1.1.1.1", "change": "removed", "details": "Target removed"},
	}
	r.DiffChanges(changes)
	output := outBuf.String()
	if !strings.Contains(output, "8.8.8.8") {
		t.Error("expected new target")
	}
	if !strings.Contains(output, "1.1.1.1") {
		t.Error("expected removed target")
	}
}

func TestDiffChangesEmpty(t *testing.T) {
	r, outBuf, _ := testRenderer()
	r.DiffChanges(nil)
	if !strings.Contains(outBuf.String(), "No changes detected") {
		t.Error("expected no changes message")
	}
}
