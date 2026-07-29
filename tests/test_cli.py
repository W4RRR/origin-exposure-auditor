"""CLI contract tests that do not contact the network."""

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from origin_audit.cli import app
from origin_audit.models import ScanReport
from origin_audit.orchestrator import ScanOutcome

runner = CliRunner()


def test_version_and_provider_commands() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.2.0"
    result = runner.invoke(app, ["providers", "list"])
    assert result.exit_code == 0
    assert "virustotal" in result.stdout
    result = runner.invoke(app, ["providers", "status"])
    assert result.exit_code == 0
    assert "SHODAN_API_KEY" in result.stdout


def test_config_and_scope_validation(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text("concurrency: 2\n", encoding="utf-8")
    result = runner.invoke(app, ["config", "validate", str(config)])
    assert result.exit_code == 0
    assert "valid" in result.stdout
    scope = tmp_path / "scope.yml"
    scope.write_text(
        "authorized_domains: [example.com]\nallow_active_validation: false\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scope", "validate", str(scope)])
    assert result.exit_code == 0
    assert "active=False" in result.stdout


def test_scan_rejects_unsafe_flag_combinations(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "-active"],
    )
    assert result.exit_code == 2
    assert "requires -authorized-scope" in result.output
    result = runner.invoke(
        app,
        ["scan", "example.com", "-active", "-passive"],
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    result = runner.invoke(app, ["scan", "not_a_domain"])
    assert result.exit_code == 2


def test_upgrade_shortcut(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        check: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["check"] = check
        observed["timeout"] = timeout
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("origin_audit.cli.subprocess.run", fake_run)
    result = runner.invoke(app, ["-up"])
    assert result.exit_code == 0
    assert "Upgrade complete" in result.stdout
    assert observed["check"] is False
    assert observed["timeout"] == 300
    assert "https://github.com/W4RRR/origin-exposure-auditor/" in str(observed["command"])


def test_urlscan_noninteractive_requires_acceptance() -> None:
    result = runner.invoke(
        app,
        [
            "-non-interactive",
            "scan",
            "example.com",
            "-submit-urlscan",
        ],
    )
    assert result.exit_code == 2
    assert "privacy" in result.output.lower()


def test_report_command(tmp_path: Path) -> None:
    source = Path(__file__).parents[1] / "examples" / "reports" / "report.json"
    target = tmp_path / "report.json"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    result = runner.invoke(app, ["report", str(target), "-format", "markdown,html"])
    assert result.exit_code == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()


def test_scan_success_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = Path(__file__).parents[1] / "examples" / "reports" / "report.json"
    report = ScanReport.model_validate_json(source.read_text(encoding="utf-8"))
    directory = tmp_path / "output" / "example.com" / "run"
    directory.mkdir(parents=True)
    audit = directory / "audit.log"
    audit.write_text("{}\n", encoding="utf-8")

    async def fake_scan(*args: object, **kwargs: object) -> ScanOutcome:
        return ScanOutcome(report=report, directory=directory, audit_log=audit)

    monkeypatch.setattr("origin_audit.cli.ScanOrchestrator.scan", fake_scan)
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "-providers",
            "dns,ct",
            "-format",
            "json,markdown",
        ],
    )
    assert result.exit_code == 0
    assert "Assessment complete" in result.stdout
    assert (directory / "report.json").exists()


def test_color_output() -> None:
    result = runner.invoke(app, ["-color", "providers", "list"], color=True)
    assert result.exit_code == 0
    assert "\033[" in result.output
