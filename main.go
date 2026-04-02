// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prodrom3/triton/internal/config"
	"github.com/prodrom3/triton/internal/diff"
	"github.com/prodrom3/triton/internal/export"
	"github.com/prodrom3/triton/internal/geo"
	"github.com/prodrom3/triton/internal/logging"
	"github.com/prodrom3/triton/internal/models"
	"github.com/prodrom3/triton/internal/network"
	"github.com/prodrom3/triton/internal/output"
	"github.com/prodrom3/triton/internal/pipeline"
	"github.com/prodrom3/triton/internal/updater"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

const maxCIDRHosts = 65536

type cliConfig struct {
	targets      []string
	db           string
	asnDB        string
	maxHops      int
	timeout      float64
	workers      int
	noTraceroute bool
	whois        bool
	dnsAll       bool
	ports        string
	portsParsed  []int
	doPorts      bool
	tls          bool
	allIPs       bool
	doHTTP       bool
	doPing       bool
	jsonOutput   bool
	quiet        bool
	verbose      bool
	outputFile   string
	csvFile      string
	htmlFile     string
	mapFile      string
	diffFile     string
	targetsFile  string
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg := parseArgs()
	if cfg == nil {
		return 1
	}

	renderer := output.NewRenderer(cfg.quiet || cfg.jsonOutput)

	stderrLevel := slog.LevelWarn
	if cfg.verbose {
		stderrLevel = slog.LevelInfo
	}
	cleanup := logging.Setup(!cfg.quiet, stderrLevel)
	defer cleanup()

	slog.Info("triton started", "targets", len(cfg.targets))
	startTime := time.Now()

	pipeCfg := pipeline.Config{
		MaxHops:      cfg.maxHops,
		Timeout:      time.Duration(cfg.timeout * float64(time.Second)),
		NoTraceroute: cfg.noTraceroute,
		AllIPs:       cfg.allIPs,
		DoWhois:      cfg.whois,
		DnsAll:       cfg.dnsAll,
		DoPorts:      cfg.doPorts,
		PortList:     cfg.portsParsed,
		DoTLS:        cfg.tls,
		DoHTTP:       cfg.doHTTP,
		DoPing:       cfg.doPing,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signals := append([]os.Signal{os.Interrupt}, extraSignals()...)
	signal.Notify(sigCh, signals...)
	go func() {
		<-sigCh
		slog.Warn("Received interrupt, shutting down...")
		cancel()
	}()

	geoReader := geo.NewReader(cfg.db, cfg.asnDB)
	defer geoReader.Close()

	showDBWarning := !geoReader.Available && !geoReader.ASNAvailable
	cache := geo.NewCache()
	whoisLimiter := network.NewRateLimiter(10, 60*time.Second)

	results := runAnalysis(ctx, cfg.targets, geoReader, cache, pipeCfg, renderer, cfg.workers, whoisLimiter)

	// Output
	if cfg.jsonOutput {
		renderer.JSONOutput(results)
	} else {
		for i, result := range results {
			renderer.Analysis(result, showDBWarning && i == 0)
		}
		renderer.SummaryTable(results)
	}

	// Save JSON to file if --output specified
	if cfg.outputFile != "" {
		data, err := models.MarshalResultsJSON(results)
		if err != nil {
			slog.Error("JSON marshal failed", "error", err)
		} else if err := os.WriteFile(cfg.outputFile, data, 0644); err != nil {
			slog.Error("Failed to write output file", "error", err)
		} else {
			slog.Info("JSON saved", "path", cfg.outputFile)
		}
	}

	// Diff
	if cfg.diffFile != "" {
		previous, err := diff.LoadPrevious(cfg.diffFile)
		if err != nil {
			renderer.Error(fmt.Sprintf("Could not load diff file: %v", err))
		} else {
			var currentDicts []map[string]any
			for _, r := range results {
				currentDicts = append(currentDicts, r.ToDict())
			}
			changes := diff.DiffResults(currentDicts, previous)
			renderer.DiffChanges(changes)
		}
	}

	// Exports
	if cfg.csvFile != "" {
		if err := export.ExportCSV(results, cfg.csvFile); err != nil {
			slog.Error("CSV export failed", "error", err)
		} else {
			slog.Info("CSV exported", "path", cfg.csvFile)
		}
	}
	if cfg.htmlFile != "" {
		if err := export.ExportHTML(results, cfg.htmlFile); err != nil {
			slog.Error("HTML export failed", "error", err)
		} else {
			slog.Info("HTML report exported", "path", cfg.htmlFile)
		}
	}
	if cfg.mapFile != "" {
		if err := export.ExportMap(results, cfg.mapFile); err != nil {
			slog.Error("Map export failed", "error", err)
		} else {
			slog.Info("Geo map exported", "path", cfg.mapFile)
		}
	}

	failCount := 0
	for _, r := range results {
		if r.HasErrors() {
			failCount++
		}
	}
	elapsed := time.Since(startTime).Round(time.Millisecond)
	slog.Info("triton finished", "targets", len(results), "failed", failCount, "duration", elapsed)

	if failCount > 0 {
		return 1
	}
	return 0
}

func runAnalysis(
	ctx context.Context,
	targets []string,
	geoReader *geo.Reader,
	cache *geo.Cache,
	cfg pipeline.Config,
	renderer *output.Renderer,
	workers int,
	whoisLimiter *network.RateLimiter,
) []models.AnalysisResult {
	if len(targets) == 1 {
		return []models.AnalysisResult{
			pipeline.AnalyzeTarget(ctx, targets[0], geoReader, cfg, cache, whoisLimiter),
		}
	}

	results := make([]models.AnalysisResult, len(targets))
	var completed atomic.Int32
	total := len(targets)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, target := range targets {
		select {
		case <-ctx.Done():
			for j := i; j < len(targets); j++ {
				results[j] = models.AnalysisResult{
					Target: targets[j], IsIP: false, Error: models.Ptr("Cancelled"),
				}
			}
			return results
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				results[idx] = models.AnalysisResult{
					Target: t, IsIP: false, Error: models.Ptr("Cancelled"),
				}
				return
			default:
			}

			results[idx] = pipeline.AnalyzeTarget(ctx, t, geoReader, cfg, cache, whoisLimiter)
			c := int(completed.Add(1))
			renderer.Progress(c, total, t)
		}(i, target)
	}

	wg.Wait()
	return results
}

func parseArgs() *cliConfig {
	cfg := &cliConfig{}

	showVersion := flag.Bool("version", false, "show version and exit")
	flag.BoolVar(showVersion, "v", false, "show version and exit")
	doUpdate := flag.Bool("update", false, "update triton to the latest release")

	flag.StringVar(&cfg.db, "db", "", "path to GeoLite2-City.mmdb (or GEOIP_DB_PATH env var)")
	flag.StringVar(&cfg.asnDB, "asn-db", "", "path to GeoLite2-ASN.mmdb")
	flag.IntVar(&cfg.maxHops, "max-hops", 20, "max traceroute hops")
	flag.Float64Var(&cfg.timeout, "timeout", 30.0, "network timeout in seconds")
	flag.IntVar(&cfg.workers, "workers", 4, "concurrent workers")
	flag.BoolVar(&cfg.noTraceroute, "no-traceroute", false, "skip traceroute")
	flag.BoolVar(&cfg.whois, "whois", false, "include WHOIS lookup")
	flag.BoolVar(&cfg.dnsAll, "dns-all", false, "query MX, TXT, NS, SOA, CNAME records")
	flag.StringVar(&cfg.ports, "ports", "", "scan ports (empty=default set, or comma-separated list)")
	flag.BoolVar(&cfg.tls, "tls", false, "inspect TLS certificate (port 443)")
	flag.BoolVar(&cfg.allIPs, "all-ips", false, "geolocate all resolved IPs")
	flag.BoolVar(&cfg.doHTTP, "http", false, "probe HTTP on open web ports (status, headers, redirects)")
	flag.BoolVar(&cfg.doPing, "ping", false, "TCP ping latency measurement")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "JSON output")
	flag.BoolVar(&cfg.quiet, "quiet", false, "suppress progress")
	flag.BoolVar(&cfg.quiet, "q", false, "suppress progress")
	flag.BoolVar(&cfg.verbose, "verbose", false, "verbose logging to stderr")
	flag.StringVar(&cfg.outputFile, "output", "", "save JSON results to file")
	flag.StringVar(&cfg.csvFile, "csv", "", "export results to CSV file")
	flag.StringVar(&cfg.htmlFile, "html", "", "export results to HTML report")
	flag.StringVar(&cfg.mapFile, "map", "", "export geo map as HTML file")
	flag.StringVar(&cfg.diffFile, "diff", "", "compare results against a previous JSON file")
	flag.StringVar(&cfg.targetsFile, "targets", "", "read targets from file (one per line)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: triton [OPTIONS] TARGET [TARGET ...]\n\n")
		fmt.Fprintf(os.Stderr, "triton - Network reconnaissance toolkit.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("triton %s\n", version)
		os.Exit(0)
	}

	if *doUpdate {
		if err := updater.Update(version); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Apply config file defaults (CLI flags override)
	applyConfigFile(cfg)

	// Detect --ports flag presence vs value
	portsSet := false
	for _, arg := range os.Args[1:] {
		if arg == "--ports" || arg == "-ports" {
			portsSet = true
			break
		}
		if strings.HasPrefix(arg, "--ports=") || strings.HasPrefix(arg, "-ports=") {
			portsSet = true
			break
		}
	}

	if portsSet {
		cfg.doPorts = true
		if cfg.ports != "" {
			ports, err := parsePorts(cfg.ports)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return nil
			}
			cfg.portsParsed = ports
		}
	}

	// Collect targets: positional args + --targets file + stdin + config file
	cfg.targets = flag.Args()

	if cfg.targetsFile != "" {
		fileTargets, err := readTargetsFile(cfg.targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading targets file: %v\n", err)
			return nil
		}
		cfg.targets = append(cfg.targets, fileTargets...)
	}

	stdinTargets := readStdinTargets()
	cfg.targets = append(cfg.targets, stdinTargets...)

	cfg.targets = expandCIDR(cfg.targets)
	cfg.targets = deduplicate(cfg.targets)

	if len(cfg.targets) == 0 {
		flag.Usage()
		return nil
	}

	if cfg.db == "" {
		cfg.db = findDBPath()
	}

	if cfg.maxHops < 1 {
		fmt.Fprintln(os.Stderr, "Error: --max-hops must be at least 1")
		return nil
	}
	if cfg.timeout <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --timeout must be greater than 0")
		return nil
	}
	if cfg.workers < 1 {
		fmt.Fprintln(os.Stderr, "Error: --workers must be at least 1")
		return nil
	}

	return cfg
}

// applyConfigFile loads .triton.json and applies values where CLI flags were not set.
func applyConfigFile(cfg *cliConfig) {
	cf := config.Load()
	if cf == nil {
		return
	}

	// Only apply config values if the CLI flag was not explicitly set.
	// We detect this by checking if the value is still the zero/default.
	if cfg.db == "" && cf.DB != "" {
		cfg.db = cf.DB
	}
	if cfg.asnDB == "" && cf.ASNDB != "" {
		cfg.asnDB = cf.ASNDB
	}
	if cfg.maxHops == 20 && cf.MaxHops != nil {
		cfg.maxHops = *cf.MaxHops
	}
	if cfg.timeout == 30.0 && cf.Timeout != nil {
		cfg.timeout = *cf.Timeout
	}
	if cfg.workers == 4 && cf.Workers != nil {
		cfg.workers = *cf.Workers
	}
	if cf.NoTraceroute != nil && *cf.NoTraceroute {
		cfg.noTraceroute = true
	}
	if cf.Whois != nil && *cf.Whois {
		cfg.whois = true
	}
	if cf.DnsAll != nil && *cf.DnsAll {
		cfg.dnsAll = true
	}
	if cf.TLS != nil && *cf.TLS {
		cfg.tls = true
	}
	if cf.AllIPs != nil && *cf.AllIPs {
		cfg.allIPs = true
	}
	if cf.HTTP != nil && *cf.HTTP {
		cfg.doHTTP = true
	}
	if cf.Ping != nil && *cf.Ping {
		cfg.doPing = true
	}
	if cf.Verbose != nil && *cf.Verbose {
		cfg.verbose = true
	}
	if cf.Quiet != nil && *cf.Quiet {
		cfg.quiet = true
	}
	if cf.Ports != "" && cfg.ports == "" {
		cfg.ports = cf.Ports
		cfg.doPorts = true
	}

	// Append config file targets (CLI targets take priority by being first)
	if len(cf.Targets) > 0 {
		cfg.targets = append(cfg.targets, cf.Targets...)
	}
}

func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, scanner.Err()
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port out of range (1-65535): %d", n)
		}
		ports = append(ports, n)
	}
	return ports, nil
}

func readStdinTargets() []string {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	var targets []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets
}

func expandCIDR(targets []string) []string {
	var expanded []string
	for _, t := range targets {
		_, ipNet, err := net.ParseCIDR(t)
		if err != nil {
			expanded = append(expanded, t)
			continue
		}

		ones, bits := ipNet.Mask.Size()
		if ones == bits {
			expanded = append(expanded, ipNet.IP.String())
			continue
		}

		hostBits := bits - ones
		if hostBits > 16 {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s (/%d too large, max /%d for expansion)\n", t, ones, bits-16)
			continue
		}

		networkIP := cloneIP(ipNet.IP)
		broadcastIP := make(net.IP, len(ipNet.IP))
		for i := range broadcastIP {
			broadcastIP[i] = ipNet.IP[i] | ^ipNet.Mask[i]
		}

		count := 0
		for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incIP(ip) {
			if len(ip) == 4 && ones < 31 {
				if ip.Equal(networkIP) || ip.Equal(broadcastIP) {
					continue
				}
			}
			expanded = append(expanded, ip.String())
			count++
			if count >= maxCIDRHosts {
				fmt.Fprintf(os.Stderr, "Warning: CIDR %s capped at %d hosts\n", t, maxCIDRHosts)
				break
			}
		}
	}
	return expanded
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func deduplicate(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	unique := make([]string, 0, len(targets))
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	return unique
}

func findDBPath() string {
	if env := os.Getenv("GEOIP_DB_PATH"); env != "" {
		return env
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	paths := []string{
		filepath.Join(home, "GeoLite2-City.mmdb"),
		filepath.Join(home, ".local", "share", "GeoIP", "GeoLite2-City.mmdb"),
	}

	if runtime.GOOS != "windows" {
		paths = append(paths,
			"/usr/share/GeoIP/GeoLite2-City.mmdb",
			"/usr/local/share/GeoIP/GeoLite2-City.mmdb",
		)
	}

	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "GeoIP", "GeoLite2-City.mmdb"))
		}
		if progdata := os.Getenv("PROGRAMDATA"); progdata != "" {
			paths = append(paths, filepath.Join(progdata, "GeoIP", "GeoLite2-City.mmdb"))
		}
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}
