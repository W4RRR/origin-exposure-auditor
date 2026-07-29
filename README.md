# origin-exposure-auditor

`origin-audit` is a defensive CLI for finding evidence of accidental origin-server
exposure behind a WAF, CDN, or reverse proxy. It correlates current DNS, public
Certificate Transparency, historical/passive DNS providers, and indexed internet data.
It reports **exposure candidates**, never an unqualified claim that an address is the
origin.

> This tool is intended exclusively for authorized security testing, defensive exposure
> assessment, and research on systems you own or are explicitly permitted to test.

It does not exploit vulnerabilities, bypass authentication, brute-force services, scan
directories or ports, evade WAF rules, submit payloads, or run denial-of-service tests.

## Why Python instead of Bash

The original proof of concept chained `curl`, `jq`, `grep`, `sort`, Shodan, and httpx.
That is useful for exploration but is not a safe maintenance boundary for paginated
APIs, typed evidence, retries, rate limits, caching, TLS parsing, multi-format reports,
or tests. Python 3.12 provides those boundaries. The Bash wrapper only bootstraps an
isolated environment and propagates the Python process exit code.

## Architecture

The pipeline is deliberately one-way:

1. Normalize and validate the authorized domain.
2. Collect passive observations through independent providers.
3. Merge candidate IPs while retaining source and evidence provenance.
4. Remove non-global addresses unless `--include-non-public` is requested.
5. Fetch one bounded baseline response from the named target.
6. Optionally validate candidates only after scope and consent checks.
7. Apply transparent scoring rules and write reproducible reports.

Every provider implements the same asynchronous contract and returns `ok`, `skipped`,
or `failed`. One provider failure never terminates the entire scan. Cache keys contain
only non-secret parameters, and complete third-party responses are not retained by
default.

## Repository layout

```text
.
├── .github/workflows/
│   ├── external-integration.yml
│   ├── lint.yml
│   ├── security.yml
│   └── tests.yml
├── data/providers.yml
├── examples/reports/
│   ├── report.csv
│   ├── report.html
│   ├── report.json
│   └── report.md
├── scripts/
│   ├── install-tools.sh
│   └── origin-audit.sh
├── src/origin_audit/
│   ├── data/providers.yml
│   ├── networking/
│   │   ├── __init__.py
│   │   ├── active_validation.py
│   │   ├── dns.py
│   │   ├── external_httpx.py
│   │   ├── favicon.py
│   │   ├── http_probe.py
│   │   ├── tls.py
│   │   └── waf_detection.py
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── censys_provider.py
│   │   ├── certificate_transparency.py
│   │   ├── dns_provider.py
│   │   ├── fofa_provider.py
│   │   ├── otx_provider.py
│   │   ├── securitytrails_provider.py
│   │   ├── shodan_provider.py
│   │   ├── urlscan_provider.py
│   │   ├── viewdns_provider.py
│   │   └── virustotal_provider.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── csv_report.py
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   ├── markdown_report.py
│   │   └── writer.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── domains.py
│   │   ├── hashing.py
│   │   ├── ips.py
│   │   ├── redaction.py
│   │   └── timestamps.py
│   ├── __init__.py
│   ├── __main__.py
│   ├── cache.py
│   ├── cli.py
│   ├── config.py
│   ├── deduplication.py
│   ├── exceptions.py
│   ├── http_client.py
│   ├── logging_config.py
│   ├── models.py
│   ├── orchestrator.py
│   ├── rate_limit.py
│   ├── scope.py
│   └── scoring.py
├── tests/
│   ├── fixtures/
│   │   ├── urlscan_search.json
│   │   └── virustotal_resolutions.json
│   ├── integration/test_live_opt_in.py
│   ├── conftest.py
│   ├── test_cli.py
│   ├── test_http_networking.py
│   ├── test_providers.py
│   ├── test_reporting_orchestrator.py
│   └── test_utils_models.py
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── Dockerfile
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
├── config.example.yml
├── docker-compose.yml
├── pyproject.toml
└── scope.example.yml
```

## Installation

Requirements: Python 3.12 or newer. Debian 12, Ubuntu 24.04+, current Kali Linux, and
recent macOS are supported. On Windows, use WSL2 or Docker Desktop.

```bash
git clone https://github.com/W4RRR/origin-exposure-auditor.git
cd origin-exposure-auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
origin-audit version
```

Quick start through the wrapper:

```bash
chmod +x scripts/origin-audit.sh
scripts/origin-audit.sh scan example.com --passive-only
```

The wrapper finds Python, creates `.venv`, installs the local package when needed,
executes the module, and returns its exact exit code.

## Configuration and API keys

Copy the examples:

```bash
cp config.example.yml config.yml
cp .env.example .env
chmod 600 .env
```

Edit `.env` locally. Never commit it. For a current shell:

```bash
export SHODAN_API_KEY="value"
export VIRUSTOTAL_API_KEY="value"
export CENSYS_API_TOKEN="value"
```

Credential precedence is:

1. system environment;
2. the file supplied with `--env-file`;
3. `.env` in the current directory;
4. `~/.config/origin-exposure-auditor/.env`.

Only presence/missing status is printed. Secret values are not logged. Censys Platform
API v3 uses `CENSYS_API_TOKEN` and optional `CENSYS_ORGANIZATION_ID`. The
`CENSYS_API_ID` and `CENSYS_API_SECRET` placeholders remain in `.env.example` only to
make legacy migration explicit; this project does not send them to the v3 API.

In CI/CD, store credentials in the platform secret manager. GitHub Actions workflows
should reference `${{ secrets.NAME }}` and must not run real provider queries for pull
requests from forks. This repository's real-provider workflow is manual, fork-blocked,
time-limited, and attached to a protected environment.

## Usage

Passive mode is the default:

| Command | What it does |
|---|---|
| `origin-audit scan example.com` | Runs the default passive assessment and writes all default report formats. |
| `origin-audit scan example.com --providers dns,ct,otx,urlscan` | Uses only current DNS, Certificate Transparency, OTX, and existing urlscan results. |
| `origin-audit scan example.com --providers all --format json,csv,markdown,html` | Tries every provider and writes JSON, CSV, Markdown, and HTML reports. Providers without credentials are skipped. |
| `origin-audit scan example.com --output-dir ./results` | Stores the run under `./results` instead of the default `./output` directory. |
| `origin-audit scan example.com --use-projectdiscovery-httpx` | Adds bounded related-hostname probing through the optional ProjectDiscovery `httpx` executable. |
| `origin-audit providers list` | Lists every built-in provider name accepted by `--providers`. |
| `origin-audit providers status` | Shows which provider credentials and optional local tools are available without printing secrets. |
| `origin-audit config validate config.example.yml` | Validates an application configuration file without running an assessment. |
| `origin-audit scope validate scope.example.yml` | Validates an authorization scope file and summarizes its active status and limits. |
| `origin-audit report ./output/example.com/TIMESTAMP/report.json` | Re-renders an existing JSON report as Markdown and HTML without querying providers again. |
| `origin-audit -up` | Reinstalls the latest `main` branch directly from the public GitHub repository. |

No API keys are required for current DNS, public Certificate Transparency, OTX public
endpoints, the named target's bounded HTTP/TLS baseline, or optional local `wafw00f`.
Missing credentials mark a provider `skipped` and the scan continues.

`--use-projectdiscovery-httpx` is optional. The adapter first verifies that the
executable identifies itself as ProjectDiscovery httpx (not the Python package's CLI),
then probes at most 200 related hostnames that resolve exclusively to global addresses.
It does not use external httpx for direct-to-IP Host/SNI validation; that safety-critical
path remains in the built-in Python implementation.

### Authorized active validation

Active validation is off by default. All three controls are mandatory:

```bash
origin-audit scan example.com -active --authorized-scope scope.yml --i-understand-and-am-authorized
```

`-active` is the compact alias for `--active-validate`. The scope file and explicit
authorization acknowledgement remain mandatory.

The scope must also set `allow_active_validation: true`, authorize the domain, and
either include each candidate IP/CIDR or explicitly set
`allow_discovered_candidates: true`. Exclusions always win. Private, loopback,
link-local, multicast, reserved, unspecified, and other non-global addresses are never
actively validated.

The active path is limited to `GET /`, one same-origin favicon request, and a verifying
TLS handshake with the target hostname as SNI. Concurrency, request rate, timeout, and
response size are bounded. There is no TLS-disable option.

Full authorized example with all providers, all report formats, verbose logging,
ProjectDiscovery `httpx`, a dedicated output directory, and the compatibility IP list:

```bash
origin-audit --config config.yml --env-file .env --timeout 15 --concurrency 10 --rate-limit 2 --verbose scan example.com --providers all --format json,csv,markdown,html --output-dir ./results -active --authorized-scope scope.yml --i-understand-and-am-authorized --use-projectdiscovery-httpx --legacy-ip-list
```

This intentionally does not include urlscan submission because submission discloses
the target to a third party.

### urlscan.io submission

Existing urlscan results are queried by default; no scan is submitted. Submission is a
separate privacy-sensitive operation:

```bash
origin-audit scan example.com --submit-urlscan --urlscan-visibility unlisted
```

Interactive execution asks for confirmation. Non-interactive execution also requires
`--accept-urlscan-privacy-risk`. Visibility must be `public`, `unlisted`, or `private`,
subject to the account's plan.

### Compatibility IP list

```bash
origin-audit scan example.com --legacy-ip-list
```

This additionally writes `example.com_ips.txt` in the current directory, one retained
candidate per line. It never replaces the structured report.

## Providers

| Provider | API key | Passive | Active | Optional |
|---|---:|---:|---:|---:|
| Current DNS | No | Yes | No | No |
| Certificate Transparency | No | Yes | No | No |
| AlienVault OTX | Optional | Yes | No | Yes |
| urlscan.io existing results | Optional | Yes | No | Yes |
| Shodan | Yes | Yes | No | Yes |
| Censys Platform v3 | Yes | Yes | No | Yes |
| VirusTotal v3 | Yes | Yes | No | Yes |
| SecurityTrails | Yes | Yes | No | Yes |
| FOFA | Yes | Yes | No | Yes |
| ViewDNS IP History API | Yes | Yes | No | Yes |
| Direct candidate validation | No | No | Yes | Yes |

The implementation follows the currently documented APIs:

- [VirusTotal v3 domain resolutions](https://docs.virustotal.com/reference/domain-object-resolutions)
- [Shodan REST API](https://developer.shodan.io/api)
- [Censys Platform API transition](https://docs.censys.com/docs/platform-api-transition-guide)
- [Censys Platform API authentication](https://docs.censys.com/reference/get-started)
- [urlscan.io API](https://urlscan.io/docs/api/)
- [SecurityTrails DNS history](https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1)
- [ViewDNS IP History API](https://viewdns.info/api/ip-history/)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [FOFA API account page](https://en.fofa.info/api/info)

Provider plans, quotas, fields, and entitlements change. The project deliberately makes
no claim that any provider is free or unlimited. It respects `429`, `Retry-After`,
bounded exponential backoff, per-provider rate settings, and access-denied responses.
Some fields or relationships may require a paid plan; that is reported as a provider
error rather than treated as an empty result.

MXToolbox is documented as a possible manual corroboration source but is not scraped.
ViewDNS automation only uses its contracted API. The tool does not automate third-party
web pages when an API or local hash computation exists.

## Scoring

Weights and thresholds live in `config.example.yml`. Typical positive rules are
historical DNS, a related certificate, matching body/favicon/title, related hostnames,
and independent-source corroboration. Negative rules include a current WAF/CDN edge,
an unrelated certificate, and stale evidence.

Every candidate includes the exact point contribution and reason. `confirmed` requires:

- score at or above the configured confirmation threshold;
- explicit active validation;
- at least two independent passive sources; and
- at least two strong active matches among body, favicon, and certificate.

Without all four, the maximum is `high_confidence`. A single provider observation can
never confirm an origin.

## Output

Each run creates:

```text
output/example.com/2026-07-24T110000Z/
├── report.json
├── report.csv
├── report.md
├── report.html
├── candidates.json
├── evidence.json
├── audit.log
├── raw/
└── screenshots/
```

The audit log records mode, command summary, sources, errors, limits, authorization
events, duration, and tool version. It never includes API keys. The `raw` directory is
empty unless a provider implements an explicitly bounded raw export and
`--save-raw-responses` is supplied. Screenshot comparison is intentionally not
implemented in this release.

Fictitious output examples using only documentation ranges are under
`examples/reports/`.

## Docker

```bash
docker compose build
docker compose run --rm origin-audit scan example.com --passive-only
```

The final image runs as a non-root user, drops capabilities, uses a read-only root
filesystem through Compose, and has no embedded credentials. It does not use host
networking or privileged mode. Output, cache, and configuration are mounted separately.

## Tests and quality

```bash
python -m pip install -e ".[dev]"
pytest
pytest --cov=origin_audit --cov-report=term-missing
pytest -m integration
ruff check .
ruff format --check .
mypy src
bandit -c pyproject.toml -r src
python -m build
```

Unit tests mock all external APIs. Integration tests are marked, disabled unless
`ORIGIN_AUDIT_RUN_INTEGRATION=1`, and require an explicitly configured laboratory
domain. The coverage gate is 85%.

## Adding a provider

1. Create one module under `src/origin_audit/providers/`.
2. Subclass `Provider`, declare credential environment names, and implement `collect`.
3. Use `ProviderHTTPClient` so retries, cache, rate limits, and sanitized errors remain
   consistent.
4. Return bounded `Evidence` and `CandidateIP` objects; never persist an entire response
   by default.
5. Register the provider in `provider_registry()` and add mocked parser/error tests.
6. Link the official API documentation and describe plan limitations.

## Migration from origin.sh

The original `origin.sh` accepted one domain, embedded a VirusTotal key, called the
VirusTotal v2 and OTX endpoints, extracted IPv4 strings with `jq`/`grep`, deduplicated
with `sort -u`, and passed the text file to ProjectDiscovery httpx.

The replacement:

- uses VirusTotal v3 and environment-only credentials;
- preserves source, timestamps, hostnames, and evidence during deduplication;
- validates IPv4 and IPv6 semantically rather than with a regex;
- isolates API failures and access-plan errors;
- computes favicon hashes locally;
- provides bounded Python HTTP/TLS observations;
- protects direct candidate connections with scope and consent; and
- retains `--legacy-ip-list` for downstream compatibility.

## Troubleshooting

- `SKIPPED`: configure the named environment variable or omit that optional provider.
- `401/403`: verify the key, plan entitlement, and Censys API Access role.
- `429`: lower the provider rate in `config.yml`; the client already respects bounded
  retry and `Retry-After`.
- no candidates: this is a valid result, not proof that the origin is hidden.
- `wafw00f` absent: the internal response-indicator check still works.
- Windows path or shell issues: run inside WSL2 or use Docker Desktop.

## Security and limitations

See [SECURITY.md](SECURITY.md). Avoid collecting targets outside written authorization.
OSINT attribution is noisy: shared hosting, recycled cloud addresses, stale DNS,
wildcard certificates, common favicons, and unrelated third-party domains all create
false positives. Correlate findings with authoritative asset inventory and firewall
logs before remediation.

Licensed under Apache-2.0.
