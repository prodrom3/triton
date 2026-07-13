# Contributing to triton

Thanks for your interest in improving triton. This document covers how to build,
test, and submit changes.

## Getting started

```bash
git clone https://github.com/prodrom3/triton
cd triton
go build ./...
go test ./...
```

triton targets Go 1.23+ and depends only on the standard library, MaxMind's
`geoip2-golang`, and `golang.org/x/net` (for ICMP).

## Before you open a pull request

Run the same checks CI runs:

```bash
make lint     # go vet + staticcheck
make test     # go test ./... -race
make vuln     # govulncheck
make sec      # gosec
```

If you have golangci-lint installed:

```bash
golangci-lint run ./...
```

Guidelines:

- Add tests for new behavior. Parsers that consume untrusted input should have a
  fuzz target (see the existing `Fuzz*` tests).
- Keep the standard-library-first, dependency-light philosophy. Discuss new
  dependencies in an issue first.
- Match the surrounding style. `gofmt` and `goimports` must be clean.
- Treat all remote data as untrusted: sanitize before terminal output, and
  escape before writing to reports.

## Responsible use

triton is a reconnaissance tool. Only scan hosts and networks you are authorized
to test. See the Responsible Use section of the README.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
