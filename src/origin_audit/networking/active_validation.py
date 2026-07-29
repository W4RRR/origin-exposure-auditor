"""Authorized, bounded comparison of candidate origins."""

from __future__ import annotations

import asyncio

import httpx

from origin_audit.models import CandidateIP, CertificateEvidence, Evidence, HttpObservation
from origin_audit.networking.favicon import discover_icon_urls, fetch_favicon
from origin_audit.networking.http_probe import probe
from origin_audit.networking.tls import fetch_certificate
from origin_audit.rate_limit import AsyncRateLimiter
from origin_audit.scope import ScopeConfig


def _certificate_related(certificate: CertificateEvidence, domain: str) -> bool:
    names = [certificate.common_name or "", *certificate.san]
    return any(name == domain or name.endswith(f".{domain}") for name in names)


async def validate_candidate(
    candidate: CandidateIP,
    *,
    domain: str,
    scope: ScopeConfig,
    client: httpx.AsyncClient,
    baseline: HttpObservation | None,
    baseline_favicon_sha256: str | None,
    maximum_bytes: int,
    limiter: AsyncRateLimiter,
) -> CandidateIP:
    """Validate one explicitly authorized candidate with GET, favicon, and TLS only."""
    scope.assert_active_allowed(domain, candidate.ip)
    candidate.active_validation_performed = True
    schemes = ("https", "http")
    body = b""
    for scheme in schemes:
        await limiter.acquire()
        port = 443 if scheme == "https" else 80
        candidate_url = f"{scheme}://{candidate.ip}:{port}/"
        try:
            async with asyncio.timeout(scope.request_timeout_seconds):
                observation, body = await probe(
                    client,
                    url=candidate_url,
                    maximum_bytes=maximum_bytes,
                    host_header=domain,
                    sni_hostname=domain if scheme == "https" else None,
                )
        except TimeoutError:
            observation = HttpObservation(url=candidate_url, error="TimeoutError")
            body = b""
        candidate.http_observations.append(observation)
        if observation.status_code is not None:
            break
    observation = candidate.http_observations[-1]
    if baseline and observation.body_sha256 == baseline.body_sha256 and observation.body_sha256:
        candidate.evidence.append(
            Evidence(
                source="active_validation",
                type="body_hash_match",
                value=observation.body_sha256,
                notes="Candidate response body matches the target baseline",
            )
        )
    if baseline and observation.title and observation.title == baseline.title:
        candidate.evidence.append(
            Evidence(
                source="active_validation",
                type="title_match",
                value=observation.title,
            )
        )
    if observation.status_code is not None and body:
        await limiter.acquire()
        try:
            async with asyncio.timeout(scope.request_timeout_seconds):
                icon = await fetch_favicon(
                    client,
                    discover_icon_urls(observation.url, body)[:1],
                    host_header=domain,
                    sni_hostname=domain if observation.url.startswith("https://") else None,
                )
        except TimeoutError:
            icon = None
        if icon:
            candidate.favicon_hashes.append(icon)
            if baseline_favicon_sha256 and icon.sha256 == baseline_favicon_sha256:
                candidate.evidence.append(
                    Evidence(
                        source="active_validation",
                        type="favicon_match",
                        value=icon.sha256,
                    )
                )
    try:
        await limiter.acquire()
        certificate = await fetch_certificate(
            candidate.ip,
            server_name=domain,
            timeout_seconds=scope.request_timeout_seconds,
            source="active_validation",
        )
        candidate.certificates.append(certificate)
        candidate.evidence.append(
            Evidence(
                source="active_validation",
                type="certificate_match"
                if _certificate_related(certificate, domain)
                else "unrelated_certificate",
                value=certificate.fingerprint_sha256 or "certificate",
            )
        )
    except (OSError, ValueError, TimeoutError) as exc:
        candidate.evidence.append(
            Evidence(
                source="active_validation",
                type="tls_error",
                value=type(exc).__name__,
                notes=str(exc)[:200],
            )
        )
    return candidate
