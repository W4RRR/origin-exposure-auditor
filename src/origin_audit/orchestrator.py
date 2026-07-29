"""End-to-end defensive scan orchestration."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from origin_audit import __version__
from origin_audit.cache import JsonCache
from origin_audit.config import AppConfig
from origin_audit.deduplication import deduplicate_candidates
from origin_audit.http_client import ProviderHTTPClient
from origin_audit.models import (
    CandidateIP,
    CertificateEvidence,
    Evidence,
    FaviconEvidence,
    HttpObservation,
    ProviderResult,
    ProviderState,
    ScanReport,
    Target,
    WAFDetection,
)
from origin_audit.networking.active_validation import validate_candidate
from origin_audit.networking.dns import resolve_related_hostnames
from origin_audit.networking.external_httpx import run_projectdiscovery_httpx
from origin_audit.networking.favicon import discover_icon_urls, fetch_favicon
from origin_audit.networking.http_probe import probe
from origin_audit.networking.tls import fetch_certificate
from origin_audit.networking.waf_detection import (
    detect_from_observation,
    load_provider_indicators,
    run_wafw00f,
)
from origin_audit.providers import provider_registry
from origin_audit.providers.base import Provider, ProviderContext
from origin_audit.providers.urlscan_provider import URLScanProvider
from origin_audit.rate_limit import AsyncRateLimiter
from origin_audit.scope import ScopeConfig
from origin_audit.scoring import score_candidates
from origin_audit.utils.ips import is_public_ip, special_address_reasons
from origin_audit.utils.timestamps import timestamp_slug, utc_now


@dataclass(slots=True)
class ScanOptions:
    """User-selected scan behavior."""

    providers: set[str]
    formats: set[str] = field(default_factory=lambda: {"json", "csv", "markdown", "html"})
    output_dir: Path = Path("output")
    include_non_public: bool = False
    active_validate: bool = False
    scope: ScopeConfig | None = None
    scope_file: Path | None = None
    no_cache: bool = False
    save_raw_responses: bool = False
    submit_urlscan: bool = False
    urlscan_visibility: str = "unlisted"
    use_projectdiscovery_httpx: bool = False
    command_summary: str = "origin-audit scan"


@dataclass(slots=True)
class ScanOutcome:
    """Report and paths needed by the CLI."""

    report: ScanReport
    directory: Path
    audit_log: Path


_LIMITATIONS = [
    "OSINT indexes may be stale, incomplete, plan-limited, or incorrectly attributed.",
    "A matching certificate, favicon, title, or historical DNS record is corroboration, not proof.",
    "Current DNS addresses commonly identify the CDN/WAF edge rather than the origin.",
    "Inactive or filtered candidates can produce false negatives.",
    "No vulnerability testing, directory discovery, authentication, or exploit payloads are used.",
]

_RECOMMENDATIONS = [
    "Restrict the origin firewall to published CDN or reverse-proxy egress ranges.",
    "Use authenticated origin pulls or mutual TLS when the provider supports it.",
    "Rotate historically exposed origin addresses after access controls are in place.",
    "Review public certificates and Certificate Transparency for unintended hostnames.",
    "Close unnecessary services and isolate administrative interfaces.",
    "Monitor firewall logs for direct-to-origin connection attempts.",
    "Treat the WAF as one control in a layered architecture, not the only control.",
]


class ScanOrchestrator:
    """Coordinate providers, bounded enrichment, validation, and scoring."""

    def __init__(
        self,
        config: AppConfig,
        environment: dict[str, str],
        *,
        provider_data_path: Path,
    ) -> None:
        self.config = config
        self.environment = environment
        self.provider_data_path = provider_data_path

    async def scan(self, target: Target, options: ScanOptions) -> ScanOutcome:
        """Run one defensive assessment."""
        started = utc_now()
        directory = options.output_dir / target.domain / timestamp_slug(started)
        directory.mkdir(parents=True, exist_ok=False)
        directory.chmod(0o700)
        (directory / "raw").mkdir()
        (directory / "screenshots").mkdir()
        audit_path = directory / "audit.log"
        self._audit(
            audit_path,
            "scan_started",
            {
                "date": started.isoformat(),
                "domain": target.domain,
                "command": options.command_summary,
                "mode": "active" if options.active_validate else "passive",
                "sources": sorted(options.providers),
                "limits": {
                    "timeout_seconds": self.config.timeout_seconds,
                    "concurrency": self.config.concurrency,
                    "rate_limit": self.config.rate_limit,
                },
                "tool_version": __version__,
            },
        )
        timeout = httpx.Timeout(self.config.timeout_seconds)
        limits = httpx.Limits(
            max_connections=self.config.concurrency,
            max_keepalive_connections=self.config.concurrency,
        )
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": self.config.user_agent},
        ) as client:
            results = await self._run_providers(target, options, client)
            candidates = [item for result in results for item in result.candidates]
            hostnames = [item for result in results for item in result.hostnames]
            candidates.extend(
                await resolve_related_hostnames(
                    hostnames,
                    target.domain,
                    timeout_seconds=self.config.timeout_seconds,
                    concurrency=self.config.concurrency,
                )
            )
            if options.use_projectdiscovery_httpx:
                external_result = await asyncio.to_thread(
                    run_projectdiscovery_httpx,
                    [target.domain, *hostnames],
                    timeout_seconds=self.config.timeout_seconds,
                )
                results.append(external_result)
                candidates.extend(external_result.candidates)
            candidates = deduplicate_candidates(candidates)
            candidates = self._handle_non_public(candidates, options.include_non_public)
            dns_result = next((item for item in results if item.provider == "dns"), None)
            dns_records = dns_result.records if dns_result else {}
            baseline, _baseline_body, baseline_favicon, baseline_certificate = await self._baseline(
                target, dns_records, client
            )
            waf = await self._detect_waf(target, baseline, dns_records)
            if waf.detected:
                current_ips = set(dns_records.get("A", [])) | set(dns_records.get("AAAA", []))
                for candidate in candidates:
                    if candidate.ip in current_ips:
                        candidate.cdn_provider = ",".join(waf.providers) or "waf_or_cdn"
            if options.submit_urlscan:
                await self._submit_urlscan(target, options, client, results)
            if options.active_validate:
                candidates = await self._active_validate(
                    target,
                    candidates,
                    options,
                    client,
                    baseline,
                    baseline_favicon,
                    audit_path,
                )
            candidates = score_candidates(candidates, self.config.scoring)
        finished = utc_now()
        report = ScanReport(
            tool_version=__version__,
            domain=target.domain,
            started_at=started,
            finished_at=finished,
            duration_seconds=(finished - started).total_seconds(),
            mode="active_authorized" if options.active_validate else "passive",
            scope_file=str(options.scope_file) if options.scope_file else None,
            authorization_acknowledged=options.active_validate and options.scope is not None,
            dns_records=dns_records,
            subdomains=sorted(set(hostnames) - {target.domain}),
            waf_detection=waf,
            baseline_http=baseline,
            baseline_certificate=baseline_certificate,
            baseline_favicon=baseline_favicon,
            candidates=candidates,
            providers=results,
            limitations=list(_LIMITATIONS),
            recommendations=list(_RECOMMENDATIONS),
        )
        errors = {item.provider: item.errors for item in results if item.errors}
        self._audit(
            audit_path,
            "scan_finished",
            {
                "date": finished.isoformat(),
                "duration_seconds": report.duration_seconds,
                "candidate_count": len(candidates),
                "errors": errors,
            },
        )
        return ScanOutcome(report=report, directory=directory, audit_log=audit_path)

    async def _run_providers(
        self,
        target: Target,
        options: ScanOptions,
        client: httpx.AsyncClient,
    ) -> list[ProviderResult]:
        registry = provider_registry()
        selected = set(registry) if "all" in options.providers else options.providers
        unknown = selected - registry.keys()
        if unknown:
            raise ValueError(f"Unknown providers: {', '.join(sorted(unknown))}")
        cache = JsonCache(self.config.cache_dir, enabled=not options.no_cache)
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run(provider: Provider) -> ProviderResult:
            settings = self.config.provider(provider.name)
            if not settings.enabled:
                return ProviderResult(
                    provider=provider.name,
                    state=ProviderState.SKIPPED,
                    message="Disabled by configuration",
                    finished_at=utc_now(),
                )
            transport = ProviderHTTPClient(
                client=client,
                cache=cache,
                provider=provider.name,
                rate=min(settings.requests_per_second, self.config.rate_limit),
                max_retries=settings.max_retries,
                cache_ttl_hours=settings.cache_ttl_hours,
            )
            context = ProviderContext(
                config=self.config,
                environment=self.environment,
                transport=transport,
                save_raw_responses=options.save_raw_responses,
            )
            async with semaphore:
                try:
                    return await provider.collect(target, context)
                except Exception as exc:
                    return ProviderResult(
                        provider=provider.name,
                        state=ProviderState.FAILED,
                        errors=[f"Unhandled provider error: {exc}"],
                        finished_at=utc_now(),
                    )

        return await asyncio.gather(*(run(registry[name]) for name in sorted(selected)))

    def _handle_non_public(
        self, candidates: list[CandidateIP], include_non_public: bool
    ) -> list[CandidateIP]:
        retained: list[CandidateIP] = []
        for candidate in candidates:
            if is_public_ip(candidate.ip):
                retained.append(candidate)
                continue
            if include_non_public:
                candidate.rejection_reasons.extend(special_address_reasons(candidate.ip))
                retained.append(candidate)
        return retained

    async def _baseline(
        self,
        target: Target,
        dns_records: dict[str, list[str]],
        client: httpx.AsyncClient,
    ) -> tuple[
        HttpObservation | None,
        bytes,
        FaviconEvidence | None,
        CertificateEvidence | None,
    ]:
        current = dns_records.get("A", []) + dns_records.get("AAAA", [])
        if not current or any(not is_public_ip(item) for item in current):
            return None, b"", None, None
        observation, body = await probe(
            client,
            url=f"https://{target.domain}/",
            maximum_bytes=self.config.max_response_bytes,
        )
        favicon = None
        if observation.status_code is not None and body:
            favicon = await fetch_favicon(
                client,
                discover_icon_urls(observation.url, body),
            )
        certificate = None
        try:
            certificate = await fetch_certificate(
                target.domain,
                server_name=target.domain,
                timeout_seconds=self.config.timeout_seconds,
                source="target_baseline",
            )
        except (OSError, ValueError, TimeoutError):
            certificate = None
        return observation, body, favicon, certificate

    async def _detect_waf(
        self,
        target: Target,
        baseline: HttpObservation | None,
        dns_records: dict[str, list[str]],
    ) -> WAFDetection:
        if baseline is None:
            return WAFDetection()
        indicators = load_provider_indicators(self.provider_data_path)
        internal = detect_from_observation(baseline, baseline.response_headers, indicators)
        current = dns_records.get("A", []) + dns_records.get("AAAA", [])
        external = None
        if current and all(is_public_ip(item) for item in current):
            external = await asyncio.to_thread(
                run_wafw00f, target.domain, self.config.timeout_seconds
            )
        if external:
            internal.detected |= external.detected
            internal.providers = sorted(set(internal.providers + external.providers))
            internal.indicators = sorted(set(internal.indicators + external.indicators))
            internal.external_tool = external.external_tool
        return internal

    async def _active_validate(
        self,
        target: Target,
        candidates: list[CandidateIP],
        options: ScanOptions,
        client: httpx.AsyncClient,
        baseline: HttpObservation | None,
        baseline_favicon: FaviconEvidence | None,
        audit_path: Path,
    ) -> list[CandidateIP]:
        scope = options.scope
        if scope is None:
            raise ValueError("Active validation requires an authorization scope")
        if not scope.allow_active_validation or not scope.domain_is_authorized(target.domain):
            raise ValueError("Scope does not authorize active validation for this domain")
        semaphore = asyncio.Semaphore(scope.max_concurrent_requests)
        limiter = AsyncRateLimiter(scope.max_requests_per_second)

        async def validate(candidate: CandidateIP) -> CandidateIP:
            if not scope.ip_is_authorized(candidate.ip):
                candidate.evidence.append(
                    Evidence(
                        source="scope",
                        type="active_validation_skipped",
                        value="outside_authorized_active_scope",
                    )
                )
                return candidate
            async with semaphore:
                self._audit(
                    audit_path,
                    "active_validation",
                    {"ip": candidate.ip, "domain": target.domain, "accepted": True},
                )
                return await validate_candidate(
                    candidate,
                    domain=target.domain,
                    scope=scope,
                    client=client,
                    baseline=baseline,
                    baseline_favicon_sha256=baseline_favicon.sha256 if baseline_favicon else None,
                    maximum_bytes=self.config.max_response_bytes,
                    limiter=limiter,
                )

        return list(await asyncio.gather(*(validate(item) for item in candidates)))

    async def _submit_urlscan(
        self,
        target: Target,
        options: ScanOptions,
        client: httpx.AsyncClient,
        results: list[ProviderResult],
    ) -> None:
        settings = self.config.provider("urlscan")
        transport = ProviderHTTPClient(
            client=client,
            cache=JsonCache(self.config.cache_dir, enabled=False),
            provider="urlscan-submit",
            rate=settings.requests_per_second,
            max_retries=settings.max_retries,
            cache_ttl_hours=0,
        )
        context = ProviderContext(
            config=self.config,
            environment=self.environment,
            transport=transport,
        )
        try:
            response = await URLScanProvider().submit(
                target, context, visibility=options.urlscan_visibility
            )
            results.append(
                ProviderResult(
                    provider="urlscan_submission",
                    message=f"Submitted with visibility {response.get('visibility')}",
                    finished_at=utc_now(),
                )
            )
        except Exception as exc:
            results.append(
                ProviderResult(
                    provider="urlscan_submission",
                    state=ProviderState.FAILED,
                    errors=[str(exc)],
                    finished_at=utc_now(),
                )
            )

    @staticmethod
    def _audit(path: Path, event: str, payload: dict[str, object]) -> None:
        entry = {"event": event, **payload}
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
