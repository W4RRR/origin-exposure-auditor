# Changelog

All notable changes follow a simplified Keep a Changelog format.

## [0.2.2] - 2026-07-29

### Fixed

- Pass SNI hostnames as strings for compatibility with current HTTPX, HTTP Core, and
  AnyIO releases.
- Isolate unexpected per-candidate active-validation failures so one IP cannot abort
  an assessment.
- Redact secret-bearing URL parameters and bearer tokens from log messages.

### Changed

- Suppress noisy dependency-level HTTP and event-loop logs even in verbose mode.
- Avoid repeated SecurityTrails retries by default when the service returns a quota or
  rate-limit response.

## [0.2.1] - 2026-07-29

### Changed

- `-active` now creates an automatic in-memory scope for the supplied domain and its
  discovered public candidates; `-authorized-scope` remains an optional strict override.

## [0.2.0] - 2026-07-29

### Added

- Single-dash CLI parameters, including `-active`, `-httpx`, `-v`, and `-up`.
- Optional `-color` terminal output for logs, provider states, and summaries.
- Illustrated README sections, a parameter guide, and a full active-assessment one-liner.

### Changed

- The authorizing scope file became the explicit authorization control for active
  validation, and the separate acknowledgement flag was removed.
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
