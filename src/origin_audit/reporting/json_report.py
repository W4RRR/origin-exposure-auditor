"""JSON report serialization."""

import json

from origin_audit.models import ScanReport


def render_json(report: ScanReport) -> str:
    """Render deterministic, readable JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
