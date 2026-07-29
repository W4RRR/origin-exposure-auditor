# Changelog

All notable changes follow a simplified Keep a Changelog format.

## [0.2.0] - 2026-07-29

### Added

- Single-dash CLI parameters, including `-active`, `-httpx`, `-v`, and `-up`.
- Optional `-color` terminal output for logs, provider states, and summaries.
- Illustrated README sections, a parameter guide, and a full active-assessment one-liner.

### Changed

- The authorizing scope file is now the explicit authorization control for active
  validation; the separate acknowledgement flag was removed.
- ProjectDiscovery integration is now exposed as `-httpx`.
- Package and default user-agent version updated to 0.2.0.

## [0.1.0] - 2026-07-24

### Added

- Passive DNS, Certificate Transparency, OTX, urlscan, Shodan, Censys Platform v3,
  VirusTotal v3, SecurityTrails, FOFA, and ViewDNS providers.
- Typed evidence, provenance-preserving deduplication, transparent scoring, cache,
  bounded retries, and rate limiting.
- Scope-gated direct validation with HTTP, favicon, and TLS comparison.
- JSON, CSV, Markdown, HTML, audit, and legacy IP-list output.
- Docker, GitHub Actions, pre-commit, tests, and security documentation.
