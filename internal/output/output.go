// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prodrom3/triton/internal/models"
)

const (
	bold   = "\033[1m"
	green  = "\033[92m"
	yellow = "\033[93m"
	red    = "\033[91m"
	cyan   = "\033[96m"
	dim    = "\033[2m"
	reset  = "\033[0m"
)

func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			return false
		}
		return fi.Mode()&os.ModeCharDevice != 0
	}
	return false
}

// Renderer handles all output formatting.
type Renderer struct {
	Out      io.Writer
	Err      io.Writer
	Quiet    bool
	outColor bool
	errColor bool
}

// NewRenderer creates a Renderer with defaults. Color detection is done once.
func NewRenderer(quiet bool) *Renderer {
	out := os.Stdout
	errW := os.Stderr
	return &Renderer{
		Out:      out,
		Err:      errW,
		Quiet:    quiet,
		outColor: colorEnabled(out),
		errColor: colorEnabled(errW),
	}
}

func (r *Renderer) c(text, color string) string {
	if r.outColor {
		return color + text + reset
	}
	return text
}

func (r *Renderer) cErr(text, color string) string {
	if r.errColor {
		return color + text + reset
	}
	return text
}

// Progress prints a progress indicator to stderr.
func (r *Renderer) Progress(current, total int, target string) {
	if r.Quiet {
		return
	}
	fmt.Fprintf(r.Err, "%s analyzing: %s\n",
		r.cErr(fmt.Sprintf("  [%d/%d]", current, total), dim), target)
}

// FormatGeo returns a formatted geolocation line.
func (r *Renderer) FormatGeo(g models.GeoResult) string {
	parts := []string{g.City}
	if g.Region != nil {
		parts = append(parts, *g.Region)
	}
	parts = append(parts, g.Country)
	location := strings.Join(parts, ", ")

	var line string
	if g.Found {
		line = fmt.Sprintf("    %s  ->  %s", g.IP, location)
		if g.Latitude != nil && g.Longitude != nil {
			line += fmt.Sprintf("  (%g, %g)", *g.Latitude, *g.Longitude)
		}
	} else {
		line = fmt.Sprintf("    %s  ->  %s", g.IP,
			r.c(fmt.Sprintf("%s, %s", g.City, g.Country), yellow))
	}

	if g.ASN != nil {
		line += fmt.Sprintf("  AS%d", *g.ASN)
		if g.ASNOrg != nil {
			line += fmt.Sprintf(" (%s)", *g.ASNOrg)
		}
	}
	return line
}

// FormatError returns a formatted error message.
func (r *Renderer) FormatError(message string) string {
	return r.c(fmt.Sprintf("  Error: %s", message), red)
}

func (r *Renderer) section(title string) {
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, r.c(fmt.Sprintf("  [%s]", title), bold))
}

func (r *Renderer) header(target string) {
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, r.c(fmt.Sprintf("  triton - Analyzing: %s", target), bold+cyan))
	fmt.Fprintln(r.Out, r.c("  "+strings.Repeat("-", 40), dim))
}

// DNS prints DNS resolution results.
func (r *Renderer) DNS(domain string, ips []string) {
	r.section("DNS Resolution")
	if len(ips) > 0 {
		for _, ip := range ips {
			fmt.Fprintf(r.Out, "    %s  ->  %s\n", domain, ip)
		}
	} else {
		fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    No IPs found for %s", domain), red))
	}
}

// DNSRecords prints extended DNS records.
func (r *Renderer) DNSRecords(records *models.DnsRecords) {
	r.section(fmt.Sprintf("DNS Records for %s", records.Domain))
	hasAny := false
	if len(records.NS) > 0 {
		fmt.Fprintf(r.Out, "    NS:    %s\n", strings.Join(records.NS, ", "))
		hasAny = true
	}
	if len(records.MX) > 0 {
		fmt.Fprintf(r.Out, "    MX:    %s\n", strings.Join(records.MX, ", "))
		hasAny = true
	}
	if len(records.CNAME) > 0 {
		fmt.Fprintf(r.Out, "    CNAME: %s\n", strings.Join(records.CNAME, ", "))
		hasAny = true
	}
	if records.SOA != nil {
		fmt.Fprintf(r.Out, "    SOA:   %s\n", *records.SOA)
		hasAny = true
	}
	for _, txt := range records.TXT {
		fmt.Fprintf(r.Out, "    TXT:   %s\n", txt)
		hasAny = true
	}
	if !hasAny {
		fmt.Fprintln(r.Out, r.c("    No additional records found", yellow))
	}
}

// Traceroute prints traceroute results.
func (r *Renderer) Traceroute(tr *models.TracerouteResult) {
	r.section(fmt.Sprintf("Traceroute to %s", tr.Target))
	if !tr.Success {
		if tr.Error != nil {
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    %s", *tr.Error), red))
		}
		return
	}
	if len(tr.Hops) == 0 {
		fmt.Fprintln(r.Out, r.c("    No hops recorded", yellow))
		return
	}
	for _, hop := range tr.Hops {
		rttStr := "* ms"
		if hop.RTT != nil {
			rttStr = fmt.Sprintf("%g ms", *hop.RTT)
		}
		hostStr := ""
		if hop.Hostname != nil {
			hostStr = fmt.Sprintf("  (%s)", *hop.Hostname)
		}
		fmt.Fprintf(r.Out, "    %3d  %-20s  %s%s\n", hop.TTL, hop.IP, rttStr, hostStr)
	}
}

// Whois prints WHOIS results.
func (r *Renderer) Whois(w *models.WhoisResult) {
	r.section(fmt.Sprintf("WHOIS for %s", w.IP))
	if !w.Success {
		if w.Error != nil {
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    %s", *w.Error), red))
		}
		return
	}
	if w.Org != nil {
		fmt.Fprintf(r.Out, "    Organization:  %s\n", *w.Org)
	}
	if w.Netname != nil {
		fmt.Fprintf(r.Out, "    Network Name:  %s\n", *w.Netname)
	}
	if w.CIDR != nil {
		fmt.Fprintf(r.Out, "    CIDR/Range:    %s\n", *w.CIDR)
	}
	if w.Description != nil {
		fmt.Fprintf(r.Out, "    Description:   %s\n", *w.Description)
	}
}

// Ports prints port scan results. Takes only open ports and the closed count.
func (r *Renderer) Ports(openPorts []models.PortResult, closedCount int) {
	r.section("Port Scan")
	if len(openPorts) == 0 {
		fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    No open ports found (%d closed)", closedCount), yellow))
		return
	}
	for _, p := range openPorts {
		line := fmt.Sprintf("    %5d/%-12s %s", p.Port, p.Service, r.c("open", green))
		if p.Banner != nil {
			line += fmt.Sprintf("  %s", *p.Banner)
		}
		fmt.Fprintln(r.Out, line)
	}
	if closedCount > 0 {
		fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    (%d closed ports not shown)", closedCount), dim))
	}
}

// TLSCert prints TLS certificate details.
func (r *Renderer) TLSCert(t *models.TlsCertResult) {
	r.section(fmt.Sprintf("TLS Certificate for %s", t.Host))
	if !t.Success {
		if t.Error != nil {
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    %s", *t.Error), red))
		}
		return
	}
	if t.SelfSigned {
		fmt.Fprintln(r.Out, r.c("    WARNING: Self-signed or unverified certificate", yellow))
	}
	if t.Subject != nil {
		fmt.Fprintf(r.Out, "    Subject:    %s\n", *t.Subject)
	}
	if t.Issuer != nil {
		fmt.Fprintf(r.Out, "    Issuer:     %s\n", *t.Issuer)
	}
	if t.NotBefore != nil {
		fmt.Fprintf(r.Out, "    Not Before: %s\n", *t.NotBefore)
	}
	if t.NotAfter != nil {
		fmt.Fprintf(r.Out, "    Not After:  %s\n", *t.NotAfter)
	}
	if len(t.SANs) > 0 {
		display := t.SANs
		if len(display) > 10 {
			display = display[:10]
		}
		fmt.Fprintf(r.Out, "    SANs:       %s\n", strings.Join(display, ", "))
		if len(t.SANs) > 10 {
			fmt.Fprintf(r.Out, "                ... and %d more\n", len(t.SANs)-10)
		}
	}
	if t.Protocol != nil {
		fmt.Fprintf(r.Out, "    Protocol:   %s\n", *t.Protocol)
	}
}

// HTTPProbe prints HTTP probe results.
func (r *Renderer) HTTPProbe(results []models.HTTPProbeResult) {
	r.section("HTTP Probe")
	for _, h := range results {
		status := r.c(fmt.Sprintf("%d", h.StatusCode), green)
		if h.StatusCode >= 400 {
			status = r.c(fmt.Sprintf("%d", h.StatusCode), red)
		} else if h.StatusCode >= 300 {
			status = r.c(fmt.Sprintf("%d", h.StatusCode), yellow)
		}
		line := fmt.Sprintf("    %s  %s", status, h.URL)
		if h.FinalURL != nil {
			line += fmt.Sprintf(" -> %s", *h.FinalURL)
		}
		fmt.Fprintln(r.Out, line)
		if h.Server != nil {
			fmt.Fprintf(r.Out, "      Server: %s\n", *h.Server)
		}
		if h.SecurityHeaders.Missing != nil {
			fmt.Fprintf(r.Out, "      Missing headers: %s\n",
				r.c(*h.SecurityHeaders.Missing, yellow))
		}
		if h.Error != nil {
			fmt.Fprintf(r.Out, "      %s\n", r.c(*h.Error, red))
		}
	}
}

// Ping prints TCP ping results.
func (r *Renderer) Ping(p *models.PingResult) {
	r.section(fmt.Sprintf("Ping %s:%d", p.IP, p.Port))
	if p.Error != nil {
		fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    %s", *p.Error), red))
		return
	}
	if p.Avg != nil {
		fmt.Fprintf(r.Out, "    %d packets, %.0f%% loss, min/avg/max = %.2f/%.2f/%.2f ms\n",
			p.Count, p.Loss, *p.Min, *p.Avg, *p.Max)
	} else {
		fmt.Fprintf(r.Out, "    %d packets, %.0f%% loss\n", p.Count, p.Loss)
	}
}

// SummaryTable prints a compact overview of all results.
func (r *Renderer) SummaryTable(results []models.AnalysisResult) {
	if len(results) < 2 {
		return
	}
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, r.c("  [Summary]", bold))
	fmt.Fprintln(r.Out)

	// Header
	fmt.Fprintf(r.Out, "    %-30s %-18s %-8s %-22s %s\n",
		r.c("TARGET", bold), r.c("IP", bold), r.c("STATUS", bold),
		r.c("GEO", bold), r.c("PORTS", bold))
	fmt.Fprintf(r.Out, "    %s\n", strings.Repeat("-", 90))

	for _, res := range results {
		target := res.Target
		if len(target) > 28 {
			target = target[:28] + ".."
		}

		ip := "-"
		if len(res.ResolvedIPs) > 0 {
			ip = res.ResolvedIPs[0]
		}
		if len(ip) > 16 {
			ip = ip[:16] + ".."
		}

		status := r.c("OK", green)
		if res.HasErrors() {
			status = r.c("FAIL", red)
		}

		geoStr := "-"
		if len(res.GeoResults) > 0 && res.GeoResults[0].Found {
			g := res.GeoResults[0]
			geoStr = fmt.Sprintf("%s, %s", g.City, g.Country)
			if len(geoStr) > 20 {
				geoStr = geoStr[:20] + ".."
			}
		}

		portsStr := "-"
		if len(res.Ports) > 0 {
			var nums []string
			for _, p := range res.Ports {
				if len(nums) >= 5 {
					nums = append(nums, "...")
					break
				}
				nums = append(nums, fmt.Sprintf("%d", p.Port))
			}
			portsStr = strings.Join(nums, ",")
		}

		fmt.Fprintf(r.Out, "    %-30s %-18s %-8s %-22s %s\n",
			target, ip, status, geoStr, portsStr)
	}
	fmt.Fprintln(r.Out)
}

// DiffChanges prints changes from a previous scan.
func (r *Renderer) DiffChanges(changes []map[string]any) {
	r.section("Changes from previous scan")
	if len(changes) == 0 {
		fmt.Fprintln(r.Out, r.c("    No changes detected", green))
		return
	}
	for _, c := range changes {
		change := fmt.Sprint(c["change"])
		target := fmt.Sprint(c["target"])
		switch change {
		case "new":
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    + %s: %s", target, c["details"]), green))
		case "removed":
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    - %s: %s", target, c["details"]), red))
		case "changed":
			field := fmt.Sprint(c["field"])
			fmt.Fprintf(r.Out, "    ~ %s.%s: %s -> %s\n", target, field, c["old"], c["new"])
		case "added":
			field := fmt.Sprint(c["field"])
			fmt.Fprintln(r.Out, r.c(fmt.Sprintf("    + %s.%s: %s", target, field, c["value"]), green))
		}
	}
}

// Error prints an error message.
func (r *Renderer) Error(message string) {
	fmt.Fprintln(r.Out, r.FormatError(message))
}

// DBWarning prints the GeoIP database warning.
func (r *Renderer) DBWarning() {
	fmt.Fprintln(r.Out, r.c("  Warning: No GeoLite2 database found.", yellow))
	fmt.Fprintln(r.Out, r.c("  Provide --db PATH or set GEOIP_DB_PATH env var.", yellow))
	fmt.Fprintln(r.Out, r.c("  Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", dim))
}

// Analysis prints a full analysis result.
func (r *Renderer) Analysis(result models.AnalysisResult, showDBWarning bool) {
	r.header(result.Target)
	if showDBWarning {
		r.DBWarning()
	}
	if result.Error != nil {
		r.Error(*result.Error)
		fmt.Fprintln(r.Out)
		return
	}
	if !result.IsIP {
		r.DNS(result.Target, result.ResolvedIPs)
	}
	if result.DnsRecords != nil {
		r.DNSRecords(result.DnsRecords)
	}
	if len(result.GeoResults) > 0 {
		r.section("Geolocation")
		for _, g := range result.GeoResults {
			fmt.Fprintln(r.Out, r.FormatGeo(g))
		}
	}
	if len(result.Ports) > 0 || result.ClosedPorts > 0 {
		r.Ports(result.Ports, result.ClosedPorts)
	}
	if result.TLS != nil {
		r.TLSCert(result.TLS)
	}
	if result.Traceroute != nil {
		r.Traceroute(result.Traceroute)
	}
	if result.Whois != nil {
		r.Whois(result.Whois)
	}
	if len(result.HTTP) > 0 {
		r.HTTPProbe(result.HTTP)
	}
	if result.Ping != nil {
		r.Ping(result.Ping)
	}
	fmt.Fprintln(r.Out)
}

// JSONOutput prints results as formatted JSON.
func (r *Renderer) JSONOutput(results []models.AnalysisResult) {
	data, err := models.MarshalResultsJSON(results)
	if err != nil {
		r.Error(fmt.Sprintf("JSON marshal error: %v", err))
		return
	}
	fmt.Fprintln(r.Out, string(data))
}
