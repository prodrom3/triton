# Security Policy

## Supported versions

Security fixes are applied to the latest released version. Please upgrade to the
most recent release before reporting an issue.

## Reporting a vulnerability

Report security vulnerabilities privately through a
[GitHub Security Advisory](https://github.com/prodrom3/triton/security/advisories/new).
Please do not open a public issue or disclose the problem publicly until a fix
is available.

When reporting, include:

- affected version (`triton --version`),
- a description of the issue and its impact,
- steps to reproduce, and
- any suggested remediation.

We aim to acknowledge reports within a few days.

## Handling of untrusted data

triton is a reconnaissance tool that connects to hosts you do not control, so it
treats all remote data as untrusted:

- Service banners, WHOIS fields, TLS certificate names, HTTP headers, DNS
  records, and reverse-DNS hostnames are stripped of control characters before
  being printed to a terminal, and are HTML-escaped in report exports.
- CSV exports neutralize spreadsheet formula injection.
- The self-updater verifies a SHA-256 checksum manifest for every downloaded
  release asset and, when a signing key is configured, an ed25519 signature over
  that manifest. Downgrades are rejected.
- `--no-private` skips targets that resolve to private, loopback, or link-local
  addresses, which is useful when target lists come from untrusted sources.

## Responsible use

You are responsible for obtaining authorization before scanning any host or
network you do not own. See the Responsible Use section of the README.
