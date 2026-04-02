// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package models

import (
	"encoding/json"
	"testing"
)

func TestGeoResultJSON(t *testing.T) {
	lat, lon := 37.386, -122.084
	region := "California"
	asn := 15169
	asnOrg := "Google LLC"

	g := GeoResult{
		IP: "8.8.8.8", City: "Mountain View", Country: "US",
		Found: true, Latitude: &lat, Longitude: &lon,
		Region: &region, ASN: &asn, ASNOrg: &asnOrg,
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(data, &m)

	if m["ip"] != "8.8.8.8" {
		t.Errorf("expected ip 8.8.8.8, got %v", m["ip"])
	}
	if m["city"] != "Mountain View" {
		t.Errorf("expected city Mountain View, got %v", m["city"])
	}
}

func TestGeoResultMinimal(t *testing.T) {
	g := GeoResult{IP: "1.1.1.1", City: "N/A", Country: "N/A", Found: false}
	data, _ := json.Marshal(g)
	var m map[string]any
	json.Unmarshal(data, &m)

	if _, ok := m["latitude"]; ok {
		t.Error("latitude should not be present")
	}
	if _, ok := m["asn"]; ok {
		t.Error("asn should not be present")
	}
}

func TestTracerouteResultJSON(t *testing.T) {
	rtt := 5.0
	tr := TracerouteResult{
		Target: "8.8.8.8", Success: true,
		Hops: []TracerouteHop{{TTL: 1, IP: "10.0.0.1", RTT: &rtt}},
	}
	data, _ := json.Marshal(tr)
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["success"] != true {
		t.Error("expected success true")
	}
}

func TestWhoisResultJSON(t *testing.T) {
	org := "Google LLC"
	netname := "GOOGLE"
	w := WhoisResult{IP: "8.8.8.8", Success: true, Org: &org, Netname: &netname}
	data, _ := json.Marshal(w)
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["org"] != "Google LLC" {
		t.Errorf("expected org Google LLC, got %v", m["org"])
	}
}

func TestDnsRecordsJSON(t *testing.T) {
	soa := "ns1.google.com"
	dr := DnsRecords{
		Domain: "google.com",
		MX:     []string{"mx1.google.com"},
		NS:     []string{"ns1.google.com"},
		SOA:    &soa,
	}
	data, _ := json.Marshal(dr)
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["domain"] != "google.com" {
		t.Errorf("expected domain google.com, got %v", m["domain"])
	}
}

func TestPortResultJSON(t *testing.T) {
	banner := "HTTP/1.1 200 OK"
	p := PortResult{Port: 80, Open: true, Service: "http", Banner: &banner}
	data, _ := json.Marshal(p)
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["banner"] != "HTTP/1.1 200 OK" {
		t.Errorf("expected banner, got %v", m["banner"])
	}
}

func TestTlsCertResultJSON(t *testing.T) {
	issuer := "Let's Encrypt"
	protocol := "TLSv1.3"
	tc := TlsCertResult{
		Host: "example.com", Success: true,
		Issuer: &issuer, Protocol: &protocol,
		SANs: []string{"example.com", "www.example.com"},
	}
	data, _ := json.Marshal(tc)
	var m map[string]any
	json.Unmarshal(data, &m)
	if m["host"] != "example.com" {
		t.Errorf("expected host example.com, got %v", m["host"])
	}
}

func TestAnalysisResultHasErrors(t *testing.T) {
	tests := []struct {
		name   string
		result AnalysisResult
		want   bool
	}{
		{
			name:   "no error",
			result: AnalysisResult{Target: "8.8.8.8", IsIP: true},
			want:   false,
		},
		{
			name:   "with error",
			result: AnalysisResult{Target: "bad", IsIP: false, Error: Ptr("fail")},
			want:   true,
		},
		{
			name:   "domain no IPs",
			result: AnalysisResult{Target: "bad.example", IsIP: false},
			want:   true,
		},
		{
			name: "failed traceroute",
			result: AnalysisResult{
				Target: "8.8.8.8", IsIP: true,
				Traceroute: &TracerouteResult{Target: "8.8.8.8", Success: false},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.HasErrors(); got != tc.want {
				t.Errorf("HasErrors() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnalysisResultToDict(t *testing.T) {
	r := AnalysisResult{
		Target:      "example.com",
		IsIP:        false,
		ResolvedIPs: []string{"93.184.216.34"},
		GeoResults: []GeoResult{
			{IP: "93.184.216.34", City: "Norwell", Country: "US", Found: true},
		},
	}
	d := r.ToDict()
	if d["target"] != "example.com" {
		t.Error("expected target example.com")
	}
	if ips, ok := d["resolved_ips"].([]any); !ok || len(ips) != 1 {
		t.Error("expected 1 resolved IP")
	}
}

func TestMarshalResultsJSONSingle(t *testing.T) {
	results := []AnalysisResult{
		{Target: "8.8.8.8", IsIP: true, ResolvedIPs: []string{"8.8.8.8"}},
	}
	data, err := MarshalResultsJSON(results)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["target"] != "8.8.8.8" {
		t.Errorf("expected target 8.8.8.8, got %v", parsed["target"])
	}
}

func TestMarshalResultsJSONMultiple(t *testing.T) {
	results := []AnalysisResult{
		{Target: "8.8.8.8", IsIP: true},
		{Target: "1.1.1.1", IsIP: true},
	}
	data, err := MarshalResultsJSON(results)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["results"]; !ok {
		t.Error("expected 'results' key for multiple results")
	}
}

func TestPtr(t *testing.T) {
	s := Ptr("hello")
	if *s != "hello" {
		t.Errorf("expected hello, got %v", *s)
	}
	n := Ptr(42)
	if *n != 42 {
		t.Errorf("expected 42, got %v", *n)
	}
}
