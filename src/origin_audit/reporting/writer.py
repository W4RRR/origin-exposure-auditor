"""Report file orchestration."""

from __future__ import annotations

import json
import os
from pathlib import Path

from origin_audit.models import ScanReport
from origin_audit.reporting.csv_report import render_csv
from origin_audit.reporting.html_report import render_html
from origin_audit.reporting.json_report import render_json
from origin_audit.reporting.markdown_report import render_markdown

_RENDERERS = {
    "json": ("report.json", render_json),
    "csv": ("report.csv", render_csv),
    "markdown": ("report.md", render_markdown),
    "html": ("report.html", render_html),
}


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def write_reports(
    directory: Path,
    report: ScanReport,
    formats: set[str],
    *,
    legacy_ip_list: bool = False,
    legacy_path: Path | None = None,
) -> list[Path]:
    """Write requested reports plus normalized candidate/evidence files."""
    unknown = formats - _RENDERERS.keys()
    if unknown:
        raise ValueError(f"Unknown report formats: {', '.join(sorted(unknown))}")
    _secure_directory(directory)
    written: list[Path] = []
    for name in sorted(formats):
        filename, renderer = _RENDERERS[name]
        path = directory / filename
        path.write_text(renderer(report), encoding="utf-8")
        written.append(path)
    candidates = directory / "candidates.json"
    candidates.write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in report.candidates],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(candidates)
    evidence = directory / "evidence.json"
    evidence.write_text(
        json.dumps(
            [
                {
                    "ip": item.ip,
                    "evidence": [entry.model_dump(mode="json") for entry in item.evidence],
                }
                for item in report.candidates
            ],
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(evidence)
    if legacy_ip_list:
        destination = legacy_path or Path(f"{report.domain}_ips.txt")
        destination.write_text(
            "".join(f"{item.ip}\n" for item in report.candidates),
            encoding="utf-8",
        )
        written.append(destination)
    return written


def render_existing_report(path: Path, formats: set[str]) -> list[Path]:
    """Re-render an existing JSON report beside the source file."""
    report = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    return write_reports(path.parent, report, formats)
