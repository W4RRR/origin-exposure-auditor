"""Standalone HTML report."""

from __future__ import annotations

from html import escape

from origin_audit.models import ScanReport


def render_html(report: ScanReport) -> str:
    """Render a compact, dependency-free HTML report."""
    cards: list[str] = []
    for candidate in report.candidates:
        reasons = "".join(
            f"<li><code>{item.points:+g}</code> {escape(item.reason)}</li>"
            for item in candidate.scoring_reasons
        )
        evidence = "".join(
            f"<li><code>{escape(item.source)}</code> / "
            f"<code>{escape(item.type)}</code>: {escape(item.value)}</li>"
            for item in candidate.evidence
        )
        cards.append(
            "<article>"
            f"<h3>{escape(candidate.ip)}</h3>"
            f"<p><span class='badge'>{escape(str(candidate.confidence))}</span> "
            f"Score {candidate.score:g}</p>"
            f"<p>Sources: {escape(', '.join(candidate.sources) or 'none')}</p>"
            f"<h4>Scoring</h4><ul>{reasons or '<li>No rule applied</li>'}</ul>"
            f"<h4>Evidence</h4><ul>{evidence or '<li>No evidence</li>'}</ul>"
            "</article>"
        )
    provider_rows = "".join(
        "<tr>"
        f"<td>{escape(item.provider)}</td><td>{escape(str(item.state))}</td>"
        f"<td>{escape(item.message or '')}</td><td>{escape('; '.join(item.errors))}</td>"
        "</tr>"
        for item in report.providers
    )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in report.limitations)
    recommendations = "".join(f"<li>{escape(item)}</li>" for item in report.recommendations)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Origin exposure assessment - {escape(report.domain)}</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 1100px; margin: 0 auto; padding: 2rem; line-height: 1.5; }}
header, article {{ border: 1px solid #7775; border-radius: .7rem; padding: 1rem;
  margin: 1rem 0; }}
.badge {{ background: #2563eb; color: white; border-radius: 1rem; padding: .2rem .6rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #7775; padding: .5rem; text-align: left; }}
code {{ font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<header>
<h1>Origin exposure assessment</h1>
<p><strong>{escape(report.domain)}</strong> - {escape(report.mode)} mode -
{report.duration_seconds:.2f}s</p>
<p>Candidates are inferences, not proof of an origin server.</p>
</header>
<h2>WAF/CDN observations</h2>
<p>Detected: {report.waf_detection.detected}. Providers:
{escape(", ".join(report.waf_detection.providers) or "none")}.</p>
<h2>Candidates</h2>
{"".join(cards) or "<p>No public candidate IPs were retained.</p>"}
<h2>Providers</h2>
<table><thead><tr><th>Provider</th><th>State</th><th>Message</th><th>Errors</th></tr>
</thead><tbody>{provider_rows}</tbody></table>
<h2>Limitations</h2><ul>{limitations}</ul>
<h2>Defensive recommendations</h2><ul>{recommendations}</ul>
</body>
</html>
"""
