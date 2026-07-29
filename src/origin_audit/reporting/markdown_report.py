"""Human-readable Markdown report."""

import json

from origin_audit.models import CandidateIP, ScanReport


def _candidate(candidate: CandidateIP) -> str:
    reasons = (
        "\n".join(f"  - {item.points:+g} {item.reason}" for item in candidate.scoring_reasons)
        or "  - No scoring rule applied"
    )
    evidence = (
        "\n".join(
            f"  - `{item.source}` / `{item.type}`: {item.value}" for item in candidate.evidence
        )
        or "  - No bounded evidence was recorded"
    )
    return (
        f"### {candidate.ip}\n\n"
        f"- Classification: `{candidate.confidence}`\n"
        f"- Score: `{candidate.score:g}`\n"
        f"- Sources: {', '.join(candidate.sources) or 'none'}\n"
        f"- Hostnames: {', '.join(candidate.hostnames) or 'none'}\n"
        f"- Active validation: `{candidate.active_validation_performed}`\n\n"
        f"Scoring reasons:\n\n{reasons}\n\nEvidence:\n\n{evidence}\n"
    )


def render_markdown(report: ScanReport) -> str:
    """Render a complete defensive report."""
    provider_rows = "\n".join(
        f"| {item.provider} | {item.state} | {item.message or ''} | {'; '.join(item.errors)} |"
        for item in report.providers
    )
    candidates = "\n".join(_candidate(item) for item in report.candidates)
    limitations = "\n".join(f"- {item}" for item in report.limitations)
    recommendations = "\n".join(f"- {item}" for item in report.recommendations)
    waf = (
        f"Detected indicators: **{report.waf_detection.detected}**. "
        f"Providers: {', '.join(report.waf_detection.providers) or 'none'}."
    )
    return f"""# Origin exposure assessment: {report.domain}

## Executive summary

This report identifies exposure candidates and supporting observations. A candidate is
not proof of an origin server. Facts, inferences, and active observations remain
separate throughout the report.

- Started: `{report.started_at.isoformat()}`
- Finished: `{report.finished_at.isoformat()}`
- Duration: `{report.duration_seconds:.2f}s`
- Mode: `{report.mode}`
- Scope: `{report.scope_file or "not used"}`
- Candidates: `{len(report.candidates)}`

## WAF/CDN observations

{waf}

## Current DNS

```json
{json.dumps(report.dns_records, indent=2, ensure_ascii=False)}
```

## Related hostnames

{", ".join(report.subdomains) or "No related hostnames were returned."}

## Candidates

{candidates or "No public candidate IPs were retained."}

## Providers

| Provider | State | Message | Errors |
|---|---|---|---|
{provider_rows}

## Limitations and possible false positives

{limitations}

## Defensive recommendations

{recommendations}

## Conclusion

Review high-confidence candidates manually, correlate them with asset inventory and
firewall logs, and do not treat any single third-party observation as confirmation.
"""
