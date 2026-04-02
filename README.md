# triton

[![CI](https://github.com/prodrom3/triton/actions/workflows/ci.yml/badge.svg)](https://github.com/prodrom3/triton/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/prodrom3/triton/releases)
[![Go 1.23+](https://img.shields.io/badge/go-1.23%2B-blue.svg)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

triton is a network reconnaissance toolkit that combines geolocation, domain resolution, and network path analysis (traceroute) to provide comprehensive insights into network entities. It also supports DNS enumeration, port scanning, TLS inspection, WHOIS lookups, ASN identification, multiple concurrent targets, CIDR ranges, export to CSV/HTML/map, and change detection against previous scans.

<p align="center">
  <img width="460" height="460" src="https://github.com/prodrom3/ArgoNet/assets/7604466/6343df52-d5e6-4c1c-b1cf-3e904b694331">
</p>

## Why "triton"?

In Greek mythology, Triton is the messenger of the sea - a god who could calm or raise the waters and who knew every current and depth of the ocean. Just as Triton surveyed and commanded the vast network of seas, this tool surveys and maps the vast network of the internet, tracing routes across its depths, uncovering what lies beneath domain names, and revealing the geography and identity behind IP addresses. The name also nods to the trident - a tool of precision and reach - reflecting triton's ability to probe ports, inspect certificates, and query registries in a single sweep.

## Features

- **IP Geolocation** - City, region, country, coordinates via GeoLite2
- **ASN Identification** - Autonomous System Number and organization via GeoLite2 ASN
- **DNS Resolution** - A + AAAA records (IPv4 and IPv6)
- **DNS Enumeration** - MX, TXT, NS, SOA, CNAME records (native Go resolver, concurrent)
- **Traceroute** - System traceroute (default, no admin needed on Windows)
- **Port Scanning** - TCP connect scan on common ports with banner grabbing (IPv4 and IPv6)
- **HTTP Probing** - Status codes, redirects, server headers, and security header audit (HSTS, CSP, X-Frame-Options)
- **TCP Ping** - Latency measurement with min/avg/max and packet loss statistics
- **TLS Inspection** - Certificate issuer, expiry, SANs, self-signed detection
- **WHOIS Lookup** - Organization, netname, CIDR from RIR databases (rate-limited with referral support)
- **CIDR Support** - Expand `192.168.1.0/24` into individual targets (up to /16, capped at 65536 hosts)
- **Multiple Targets** - Concurrent analysis with configurable workers and summary table
- **Export** - CSV, self-contained HTML report, and Leaflet geo map (XSS-safe)
- **Diff Mode** - Compare current results against a previous JSON scan
- **JSON Output** - Structured output for scripting, `--output FILE` for saving
- **Target Sources** - Positional args, `--targets FILE`, stdin piping, config file
- **Config File** - `.triton.json` for saving default flag combinations
- **Self-update** - `--update` to download the latest release from GitHub
- **Graceful Shutdown** - Ctrl+C / SIGTERM cancels all in-flight operations via context propagation
- **Logging** - Timestamped log files with automatic rotation, `--verbose` mode
- **Cross-platform** - Builds for Linux, macOS, and Windows (amd64 and arm64)

## Installation

### Prerequisites

- Go >= 1.23
- Git (for `go install`)

### GeoLite2 Databases

Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free account required):
- **GeoLite2-City.mmdb** - geolocation (city, region, country, coordinates)
- **GeoLite2-ASN.mmdb** - ASN identification (optional)

Set the path via `--db`, the `GEOIP_DB_PATH` environment variable, or place the file in your home directory. On Windows, `%APPDATA%\GeoIP\` and `%PROGRAMDATA%\GeoIP\` are also searched.

### Install

```bash
# Install from source
go install github.com/prodrom3/triton@latest

# Or clone and build (with version stamping)
git clone https://github.com/prodrom3/triton.git
cd triton
make build

# Or build manually
go build -ldflags "-X main.version=$(cat VERSION)" -o triton .

# Run directly without installing
go run . 8.8.8.8
```

## Usage

```bash
triton [OPTIONS] TARGET [TARGET ...]
cat targets.txt | triton [OPTIONS]
```

### Flags

| Flag | Description |
|---|---|
| `TARGET` | IPs, domains, or CIDR ranges (also reads from stdin) |
| `--db PATH` | Path to GeoLite2-City.mmdb (or `GEOIP_DB_PATH` env var) |
| `--asn-db PATH` | Path to GeoLite2-ASN.mmdb |
| `--dns-all` | Query MX, TXT, NS, SOA, CNAME records |
| `--ports [LIST]` | Scan ports (default set, or comma-separated: `--ports 22,80,443`) |
| `--tls` | Inspect TLS certificate on port 443 |
| `--whois` | WHOIS lookup (rate-limited to 10/minute) |
| `--http` | Probe HTTP on open web ports (status, headers, redirects) |
| `--ping` | TCP ping latency measurement (3 probes on port 80) |
| `--all-ips` | Geolocate all resolved IPs, not just the first |
| `--no-traceroute` | Skip traceroute |
| `--max-hops N` | Maximum traceroute hops (default: 20) |
| `--timeout SECS` | Network operation timeout (default: 30) |
| `--workers N` | Concurrent workers (default: 4) |
| `--json` | JSON output |
| `--csv FILE` | Export results to CSV |
| `--html FILE` | Export results to HTML report |
| `--map FILE` | Export geo map as HTML (Leaflet/OpenStreetMap) |
| `--diff FILE` | Compare results against a previous JSON file |
| `--output FILE` | Save JSON results to file |
| `--targets FILE` | Read targets from file (one per line, # comments) |
| `-q, --quiet` | Suppress progress output |
| `--verbose` | Verbose logging to stderr (shows probe timings) |
| `--update` | Update triton to the latest release |
| `-v, --version` | Show version and exit |

### Examples

```bash
# Basic recon
triton 8.8.8.8

# Full sweep on a domain
triton --dns-all --ports default --tls --whois example.com

# Multiple targets concurrently
triton 8.8.8.8 1.1.1.1 example.com

# Scan a subnet
triton --ports default --no-traceroute 192.168.1.0/24

# DNS enumeration only
triton --dns-all --no-traceroute example.com

# TLS certificate check
triton --tls --no-traceroute example.com

# Geolocation with ASN and coordinates
triton --db city.mmdb --asn-db asn.mmdb --all-ips example.com

# Pipe targets from a file
cat targets.txt | triton --no-traceroute --json

# Export to HTML report and geo map
triton --html report.html --map map.html 8.8.8.8 1.1.1.1

# Export to CSV
triton --csv results.csv --no-traceroute example.com

# HTTP probe - check status codes and security headers
triton --http --ports default example.com

# TCP ping latency
triton --ping --no-traceroute 8.8.8.8

# Read targets from a file
triton --targets hosts.txt --no-traceroute --json

# Track changes over time (self-contained, no shell redirection)
triton --output baseline.json example.com
# ... later ...
triton example.com --diff baseline.json

# Verbose mode (shows probe durations)
triton --verbose 8.8.8.8

# JSON output for scripting
triton --json 8.8.8.8 | jq '.geolocation'

# Self-update to latest release
triton --update
```

## Configuration File

Create a `.triton.json` in your project directory or home directory to set default options:

```json
{
  "db": "/path/to/GeoLite2-City.mmdb",
  "asn_db": "/path/to/GeoLite2-ASN.mmdb",
  "timeout": 15,
  "workers": 8,
  "dns_all": true,
  "tls": true,
  "whois": true,
  "http": true,
  "ping": true,
  "ports": "22,80,443,8080"
}
```

CLI flags always override config file values. The config file is loaded from the current directory first, then the home directory.

## Project Structure

```
triton/
  main.go                       - Entry point (CLI, signal handling, orchestration)
  main_test.go                  - CLI function tests (CIDR, ports, dedup)
  go.mod                        - Go module definition
  VERSION                       - Semver version string
  Makefile                      - Build, test, lint, cover targets
  .goreleaser.yml               - Cross-platform release config
  internal/
    models/
      models.go                 - Data types (GeoResult, DnsRecords, PortResult, ...)
      models_test.go            - Model serialization and HasErrors tests
    geo/
      geo.go                    - GeoIPReader (city + ASN, lock-free mmap reads)
      cache.go                  - Bounded result cache (per-map RWMutex)
      ip.go                     - IP parsing helper
      cache_test.go             - Cache get/set/eviction/concurrency tests
    network/
      network.go                - DNS resolution, reverse DNS, IP validation
      whois.go                  - WHOIS lookup with encapsulated rate limiter
      network_test.go           - IP validation, WHOIS sanitization, rate limiter tests
    dns/
      dns.go                    - DNS record enumeration (native Go resolver, concurrent)
      dns_test.go               - DNS query tests
    scanner/
      scanner.go                - Port scanning (IPv4/IPv6), banner grabbing, TLS inspection
      scanner_test.go           - Scanner tests (local TCP listener, TLS, IPv6)
    httpprobe/
      httpprobe.go              - HTTP probing (status, redirects, server, security headers)
    ping/
      ping.go                   - TCP ping latency measurement
    config/
      config.go                 - .triton.json config file loader
    tracer/
      tracer.go                 - System traceroute (cross-platform, timeout hop capture)
      tracer_test.go            - Traceroute output parsing tests (Linux + Windows)
    pipeline/
      pipeline.go               - Concurrent analysis with probe timing and context propagation
      pipeline_test.go          - Pipeline tests with mock GeoLookup interface
    output/
      output.go                 - Renderer (ANSI colors, cached detection)
      output_test.go            - Output formatting and rendering tests
    export/
      export.go                 - CSV, HTML report (XSS-escaped), Leaflet geo map
      export_test.go            - Export and XSS escaping tests
    diff/
      diff.go                   - JSON result comparison (object, array, wrapped formats)
      diff_test.go              - Diff detection tests
    logging/
      logging.go                - slog multi-handler, file rotation, configurable verbosity
      logging_test.go           - Log rotation tests
    updater/
      updater.go                - Self-update from GitHub releases
  .github/workflows/ci.yml     - GitHub Actions CI (test matrix + lint)
```

## Development

```bash
# Build with version stamping
make build

# Run tests
make test

# Run tests with coverage
make cover

# Lint (go vet + staticcheck)
make lint

# Or use Go directly
go test ./... -v
go vet ./...
go build -o triton .
go run . 8.8.8.8
```

## Dependencies

- [geoip2-golang](https://github.com/oschwald/geoip2-golang) v1.13.0 - MaxMind GeoLite2 database reader (required for geolocation)
- Go standard library for everything else (networking, TLS, DNS, CLI, JSON, CSV, HTTP)

## Contributing

Contributions to triton are welcome. Please fork the repository, make improvements, and submit pull requests.

## Author

Created by [prodrom3](https://github.com/prodrom3) / [radamic](https://github.com/radamic)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any problems or have suggestions, please open an issue on the GitHub repository.
