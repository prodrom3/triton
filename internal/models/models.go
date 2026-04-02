// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package models

import "encoding/json"

// GeoResult holds geolocation data for a single IP.
type GeoResult struct {
	IP        string   `json:"ip"`
	City      string   `json:"city"`
	Country   string   `json:"country"`
	Found     bool     `json:"found"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	Region    *string  `json:"region,omitempty"`
	ASN       *int     `json:"asn,omitempty"`
	ASNOrg    *string  `json:"asn_org,omitempty"`
}

// TracerouteHop represents a single hop in a traceroute.
type TracerouteHop struct {
	TTL      int      `json:"ttl"`
	IP       string   `json:"ip"`
	RTT      *float64 `json:"rtt"`
	Hostname *string  `json:"hostname,omitempty"`
}

// TracerouteResult holds the full traceroute output for a target.
type TracerouteResult struct {
	Target  string          `json:"target"`
	Success bool            `json:"success"`
	Hops    []TracerouteHop `json:"hops,omitempty"`
	Error   *string         `json:"error,omitempty"`
}

// WhoisResult holds WHOIS lookup data for an IP.
type WhoisResult struct {
	IP          string  `json:"ip"`
	Success     bool    `json:"success"`
	Netname     *string `json:"netname,omitempty"`
	Org         *string `json:"org,omitempty"`
	CIDR        *string `json:"cidr,omitempty"`
	Description *string `json:"description,omitempty"`
	Error       *string `json:"error,omitempty"`
}

// DnsRecords holds extended DNS record data for a domain.
type DnsRecords struct {
	Domain string   `json:"domain"`
	MX     []string `json:"mx,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	NS     []string `json:"ns,omitempty"`
	SOA    *string  `json:"soa,omitempty"`
	CNAME  []string `json:"cname,omitempty"`
}

// PortResult holds the result of a single port scan.
type PortResult struct {
	Port    int     `json:"port"`
	Open    bool    `json:"open"`
	Service string  `json:"service"`
	Banner  *string `json:"banner,omitempty"`
}

// TlsCertResult holds TLS certificate information.
type TlsCertResult struct {
	Host       string   `json:"host"`
	Success    bool     `json:"success"`
	Issuer     *string  `json:"issuer,omitempty"`
	Subject    *string  `json:"subject,omitempty"`
	NotBefore  *string  `json:"not_before,omitempty"`
	NotAfter   *string  `json:"not_after,omitempty"`
	SANs       []string `json:"sans,omitempty"`
	SelfSigned bool     `json:"self_signed,omitempty"`
	Protocol   *string  `json:"protocol,omitempty"`
	Error      *string  `json:"error,omitempty"`
}

// HTTPProbeResult holds HTTP response metadata for a probed URL.
type HTTPProbeResult struct {
	URL             string          `json:"url"`
	StatusCode      int             `json:"status_code,omitempty"`
	Status          string          `json:"status,omitempty"`
	Server          *string         `json:"server,omitempty"`
	FinalURL        *string         `json:"final_url,omitempty"`
	SecurityHeaders SecurityHeaders `json:"security_headers,omitempty"`
	Error           *string         `json:"error,omitempty"`
}

// SecurityHeaders tracks the presence of key HTTP security headers.
type SecurityHeaders struct {
	HSTS                *string `json:"hsts,omitempty"`
	CSP                 *string `json:"csp,omitempty"`
	XFrameOptions       *string `json:"x_frame_options,omitempty"`
	XContentTypeOptions *string `json:"x_content_type_options,omitempty"`
	XXSSProtection      *string `json:"x_xss_protection,omitempty"`
	Missing             *string `json:"missing,omitempty"`
}

// PingResult holds TCP ping latency measurements.
type PingResult struct {
	IP    string    `json:"ip"`
	Port  int       `json:"port"`
	Count int       `json:"count"`
	RTTs  []float64 `json:"rtts,omitempty"`
	Min   *float64  `json:"min_ms,omitempty"`
	Max   *float64  `json:"max_ms,omitempty"`
	Avg   *float64  `json:"avg_ms,omitempty"`
	Loss  float64   `json:"loss_pct"`
	Error *string   `json:"error,omitempty"`
}

// AnalysisResult is the composite result for a single target.
type AnalysisResult struct {
	Target      string            `json:"target"`
	IsIP        bool              `json:"is_ip"`
	ResolvedIPs []string          `json:"resolved_ips,omitempty"`
	GeoResults  []GeoResult       `json:"geolocation,omitempty"`
	Traceroute  *TracerouteResult `json:"traceroute,omitempty"`
	Whois       *WhoisResult      `json:"whois,omitempty"`
	DnsRecords  *DnsRecords       `json:"dns_records,omitempty"`
	Ports       []PortResult      `json:"ports,omitempty"`
	ClosedPorts int               `json:"closed_ports,omitempty"`
	TLS         *TlsCertResult    `json:"tls,omitempty"`
	HTTP        []HTTPProbeResult `json:"http,omitempty"`
	Ping        *PingResult       `json:"ping,omitempty"`
	Error       *string           `json:"error,omitempty"`
}

// HasErrors returns true if this result has any errors.
func (r *AnalysisResult) HasErrors() bool {
	if r.Error != nil {
		return true
	}
	if !r.IsIP && len(r.ResolvedIPs) == 0 {
		return true
	}
	if r.Traceroute != nil && !r.Traceroute.Success {
		return true
	}
	return false
}

// ToDict returns a JSON-compatible map by marshaling via struct tags
// and unmarshaling back into map[string]any. This avoids hand-written
// serialization that could drift from the struct tags.
func (r *AnalysisResult) ToDict() map[string]any {
	return structToMap(r)
}

func structToMap(v any) map[string]any {
	data, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}

// Ptr is a helper to create a pointer to a value.
func Ptr[T any](v T) *T {
	return &v
}

// MarshalResultsJSON marshals results as JSON matching the expected output format.
func MarshalResultsJSON(results []AnalysisResult) ([]byte, error) {
	if len(results) == 1 {
		return json.MarshalIndent(results[0], "", "  ")
	}
	wrapper := map[string]any{"results": results}
	return json.MarshalIndent(wrapper, "", "  ")
}
