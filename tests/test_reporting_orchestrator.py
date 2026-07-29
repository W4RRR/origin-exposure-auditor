"""Reporting and high-level orchestration tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from origin_audit.config import AppConfig, ProviderSettings
from origin_audit.models import (
    CandidateIP,
    Evidence,
    HttpObservation,
    ProviderResult,
    ScanReport,
    Target,
    WAFDetection,
)
from origin_audit.orchestrator import ScanOptions, ScanOrchestrator
from origin_audit.providers.base import Provider, ProviderContext
from origin_audit.reporting.csv_report import render_csv
from origin_audit.reporting.html_report import render_html
from origin_audit.reporting.json_report import render_json
from origin_audit.reporting.markdown_report import render_markdown
from origin_audit.reporting.writer import render_existing_report, write_reports
from origin_audit.scope import ScopeConfig


def sample_report() -> ScanReport:
    candidate = CandidateIP(
        ip="203.0.113.10",
        sources=["virustotal"],
        hostnames=["example.com"],
        evidence=[
            Evidence(
                source="virustotal",
                type="historical_dns",
                value="example.com resolved to 203.0.113.10",
            )
        ],
        score=25,
    )
    started = datetime(2026, 7, 24, 11, tzinfo=UTC)
    return ScanReport(
        tool_version="0.2.0",
        domain="example.com",
        started_at=started,
        finished_at=started,
        duration_seconds=0,
        mode="passive",
        dns_records={"A": ["192.0.2.10"]},
        candidates=[candidate],
        providers=[ProviderResult(provider="virustotal")],
        limitations=["Example limitation"],
        recommendations=["Example recommendation"],
    )


def test_report_renderers_and_writer(tmp_path: Path) -> None:
    report = sample_report()
    assert '"domain": "example.com"' in render_json(report)
    assert "203.0.113.10" in render_csv(report)
    assert "# Origin exposure assessment" in render_markdown(report)
    assert "<!doctype html>" in render_html(report)
    directory = tmp_path / "report"
    written = write_reports(
        directory,
        report,
        {"json", "csv", "markdown", "html"},
        legacy_ip_list=True,
        legacy_path=tmp_path / "example.com_ips.txt",
    )
    assert (directory / "report.json").exists()
    assert (directory / "candidates.json").exists()
    assert (tmp_path / "example.com_ips.txt").read_text() == "203.0.113.10\n"
    assert len(written) == 7
    rerendered = render_existing_report(directory / "report.json", {"markdown", "html"})
    assert len(rerendered) == 4  # formats plus candidates/evidence
    with pytest.raises(ValueError):
        write_reports(directory, report, {"unknown"})


@pytest.mark.asyncio
async def test_orchestrator_passive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig(output_dir=tmp_path / "output", cache_dir=tmp_path / "cache")
    orchestrator = ScanOrchestrator(config, {}, provider_data_path=tmp_path / "providers.yml")
    candidate = CandidateIP(
        ip="203.0.113.10",
        sources=["virustotal"],
        evidence=[Evidence(source="virustotal", type="historical_dns", value="example")],
    )

    async def fake_providers(*args: Any, **kwargs: Any) -> list[ProviderResult]:
        return [
            ProviderResult(
                provider="dns",
                candidates=[],
                records={"A": ["192.0.2.10"], "AAAA": []},
            ),
            ProviderResult(
                provider="virustotal",
                candidates=[candidate],
                hostnames=["api.example.com"],
            ),
        ]

    async def fake_resolve(*args: Any, **kwargs: Any) -> list[CandidateIP]:
        return []

    async def fake_baseline(*args: Any, **kwargs: Any) -> tuple[Any, bytes, Any, Any]:
        return None, b"", None, None

    async def fake_waf(*args: Any, **kwargs: Any) -> WAFDetection:
        return WAFDetection()

    monkeypatch.setattr(orchestrator, "_run_providers", fake_providers)
    monkeypatch.setattr("origin_audit.orchestrator.resolve_related_hostnames", fake_resolve)
    monkeypatch.setattr(orchestrator, "_baseline", fake_baseline)
    monkeypatch.setattr(orchestrator, "_detect_waf", fake_waf)
    monkeypatch.setattr("origin_audit.orchestrator.is_public_ip", lambda _: True)
    outcome = await orchestrator.scan(
        Target(domain="example.com"),
        ScanOptions(providers={"dns", "virustotal"}, output_dir=config.output_dir),
    )
    assert outcome.report.domain == "example.com"
    assert outcome.report.candidates[0].ip == "203.0.113.10"
    assert outcome.audit_log.exists()
    entries = [
        json.loads(line) for line in outcome.audit_log.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["event"] for item in entries] == ["scan_started", "scan_finished"]


@pytest.mark.asyncio
async def test_run_providers_unknown(
    tmp_path: Path,
) -> None:
    config = AppConfig(output_dir=tmp_path / "out", cache_dir=tmp_path / "cache")
    orchestrator = ScanOrchestrator(config, {}, provider_data_path=tmp_path / "providers.yml")
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="Unknown providers"):
            await orchestrator._run_providers(
                Target(domain="example.com"),
                ScanOptions(providers={"unknown"}),
                client,
            )


@pytest.mark.asyncio
async def test_run_providers_success_disabled_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TestProvider(Provider):
        name = "test"

        async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
            del target, context
            return ProviderResult(provider=self.name, message="ok")

    class FailingProvider(Provider):
        name = "fail"

        async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
            del target, context
            raise RuntimeError("provider failure")

    config = AppConfig(
        cache_dir=tmp_path / "cache",
        providers={
            "test": ProviderSettings(requests_per_second=1000),
            "fail": ProviderSettings(requests_per_second=1000),
        },
    )
    orchestrator = ScanOrchestrator(config, {}, provider_data_path=tmp_path / "data.yml")
    monkeypatch.setattr(
        "origin_audit.orchestrator.provider_registry",
        lambda: {"test": TestProvider(), "fail": FailingProvider()},
    )
    async with httpx.AsyncClient() as client:
        results = await orchestrator._run_providers(
            Target(domain="example.com"),
            ScanOptions(providers={"test", "fail"}),
            client,
        )
        assert {item.provider for item in results} == {"test", "fail"}
        assert next(item for item in results if item.provider == "fail").errors
        config.providers["test"].enabled = False
        disabled = await orchestrator._run_providers(
            Target(domain="example.com"),
            ScanOptions(providers={"test"}),
            client,
        )
        assert disabled[0].message == "Disabled by configuration"


@pytest.mark.asyncio
async def test_orchestrator_baseline_waf_active_and_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = AppConfig(cache_dir=tmp_path / "cache")
    orchestrator = ScanOrchestrator(config, {}, provider_data_path=tmp_path / "data.yml")
    observation = HttpObservation(
        url="https://example.com/",
        status_code=200,
        body_sha256="hash",
    )

    async def fake_probe(*args: Any, **kwargs: Any) -> tuple[HttpObservation, bytes]:
        return observation, b"<html></html>"

    async def fake_favicon(*args: Any, **kwargs: Any) -> None:
        return None

    async def fake_certificate(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr("origin_audit.orchestrator.probe", fake_probe)
    monkeypatch.setattr("origin_audit.orchestrator.fetch_favicon", fake_favicon)
    monkeypatch.setattr("origin_audit.orchestrator.fetch_certificate", fake_certificate)
    monkeypatch.setattr("origin_audit.orchestrator.is_public_ip", lambda _: True)
    async with httpx.AsyncClient() as client:
        baseline, body, favicon, certificate = await orchestrator._baseline(
            Target(domain="example.com"),
            {"A": ["192.0.2.10"]},
            client,
        )
    assert baseline is observation
    assert body
    assert favicon is None
    assert certificate is None

    monkeypatch.setattr(
        "origin_audit.orchestrator.load_provider_indicators",
        lambda _: {"edge": {"headers": [], "server": [], "cookies": []}},
    )
    monkeypatch.setattr(
        "origin_audit.orchestrator.detect_from_observation",
        lambda *args: WAFDetection(),
    )
    monkeypatch.setattr(
        "origin_audit.orchestrator.run_wafw00f",
        lambda *args: WAFDetection(detected=True, providers=["example-edge"]),
    )
    detected = await orchestrator._detect_waf(
        Target(domain="example.com"), observation, {"A": ["192.0.2.10"]}
    )
    assert detected.detected

    monkeypatch.setattr("origin_audit.scope.is_public_ip", lambda _: True)
    scope = ScopeConfig(
        authorized_domains=["example.com"],
        authorized_ips=["203.0.113.0/24"],
        excluded_ips=["203.0.113.11"],
        allow_active_validation=True,
    )

    async def fake_validate(candidate: CandidateIP, **kwargs: Any) -> CandidateIP:
        candidate.active_validation_performed = True
        return candidate

    monkeypatch.setattr("origin_audit.orchestrator.validate_candidate", fake_validate)
    audit = tmp_path / "audit.log"
    async with httpx.AsyncClient() as client:
        validated = await orchestrator._active_validate(
            Target(domain="example.com"),
            [CandidateIP(ip="203.0.113.10"), CandidateIP(ip="203.0.113.11")],
            ScanOptions(
                providers={"dns"},
                active_validate=True,
                scope=scope,
            ),
            client,
            observation,
            None,
            audit,
        )
    assert validated[0].active_validation_performed
    assert validated[1].evidence[-1].type == "active_validation_skipped"

    async def fake_submit(*args: Any, **kwargs: Any) -> dict[str, object]:
        return {"visibility": "unlisted"}

    monkeypatch.setattr("origin_audit.orchestrator.URLScanProvider.submit", fake_submit)
    results: list[ProviderResult] = []
    async with httpx.AsyncClient() as client:
        await orchestrator._submit_urlscan(
            Target(domain="example.com"),
            ScanOptions(providers={"urlscan"}, submit_urlscan=True),
            client,
            results,
        )
    assert results[0].provider == "urlscan_submission"
