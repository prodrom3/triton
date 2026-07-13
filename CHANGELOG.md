# Changelog

All notable changes to this project are documented here. The format is based on
Keep a Changelog, and the project aims to follow semantic versioning.

## [Unreleased]

### Added
- TLS certificate expiry reporting: `days_until_expiry`, an `expired` flag, and
  a `--cert-expiry-days` threshold that highlights certificates nearing expiry.
- HTTP probe enrichment: page title extraction, a light technology fingerprint,
  a configurable `--user-agent`, and repeatable `--header` request headers.
- `--resolver` to send DNS, reverse DNS, and record queries to a custom server.
- `--jsonl` streaming output: one JSON object per target as it completes, which
  bounds memory on large scans.
- `--icmp` ICMP echo ping, with an unprivileged datagram socket and a raw-socket
  fallback, plus a clear message when neither is permitted.
- `--completion bash|zsh|fish` to print a shell completion script.
- Dockerfile, shell completions, and standard project files.
- Fuzz tests for the traceroute, WHOIS, port-list, and diff parsers.
- Unit tests for the HTTP probe, ping, and config packages.
- CI: golangci-lint, a coverage floor, SBOM generation, and build provenance
  attestation on releases. GitHub Actions are pinned to commit SHAs.

### Changed
- Traceroute hop parsing tolerates the "IP (host)" format emitted by busybox and
  some BSD variants.

## Earlier

See the Git history and GitHub releases for changes prior to this changelog.
