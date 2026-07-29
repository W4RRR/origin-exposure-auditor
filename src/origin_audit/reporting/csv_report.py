"""Candidate summary CSV rendering."""

import csv
import io

from origin_audit.models import ScanReport


def render_csv(report: ScanReport) -> str:
    """Render one row per candidate."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "ip",
            "confidence",
            "score",
            "sources",
            "hostnames",
            "ports",
            "asn",
            "organization",
            "last_seen",
            "active_validation_performed",
        ],
    )
    writer.writeheader()
    for candidate in report.candidates:
        writer.writerow(
            {
                "ip": candidate.ip,
                "confidence": candidate.confidence,
                "score": candidate.score,
                "sources": ";".join(candidate.sources),
                "hostnames": ";".join(candidate.hostnames),
                "ports": ";".join(str(item) for item in candidate.ports),
                "asn": candidate.asn or "",
                "organization": candidate.organization or "",
                "last_seen": candidate.last_seen.isoformat() if candidate.last_seen else "",
                "active_validation_performed": candidate.active_validation_performed,
            }
        )
    return output.getvalue()
