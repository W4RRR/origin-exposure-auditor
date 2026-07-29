# Security policy

## Supported versions

The latest released minor version receives security fixes. Pre-release code on the
default branch may change without compatibility guarantees.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose secrets, bypass scope
checks, enable SSRF, or cause unauthorized network activity. Use the repository's
private security-advisory workflow. Include:

- affected version and platform;
- minimal reproduction using `example.com` and documentation-only IP ranges;
- expected versus actual authorization behavior; and
- whether credentials or third-party data were exposed.

Do not include real API keys, private targets, customer data, or complete provider
responses. Maintainers should acknowledge a report within seven days and provide a
remediation plan after validation.

## Security invariants

- Active candidate connections require `-active`. The CLI creates a run-scoped policy
  for the exact domain and its discovered public candidates, or loads the stricter
  policy supplied with `-authorized-scope`.
- Scope exclusions override inclusions.
- Non-global IPs are never actively validated.
- TLS verification is always enabled.
- Subprocesses use argument arrays, no shell interpolation, and timeouts.
- API secrets are sourced from the environment hierarchy and must not enter logs,
  reports, cache keys, issue attachments, or test fixtures.
- Provider failures are isolated and retries are finite.
- Unit tests do not contact real providers.

## Operator responsibilities

Obtain written authorization, minimize data retention, choose appropriate urlscan
visibility, respect provider terms and quotas, and review the generated scope before
enabling active validation.
