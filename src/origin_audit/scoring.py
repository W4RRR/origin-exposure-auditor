"""Transparent, configurable candidate scoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from origin_audit.config import ScoringSettings
from origin_audit.models import CandidateIP, Confidence, ScoringContribution


def _add(
    contributions: list[ScoringContribution],
    *,
    rule: str,
    points: float,
    reason: str,
) -> None:
    contributions.append(ScoringContribution(rule=rule, points=points, reason=reason))


def score_candidate(
    candidate: CandidateIP,
    settings: ScoringSettings,
    *,
    now: datetime | None = None,
) -> CandidateIP:
    """Apply each rule at most once and store its explanation."""
    current = now or datetime.now(UTC)
    types = {evidence.type for evidence in candidate.evidence}
    contributions: list[ScoringContribution] = []
    rules = (
        ("historical_dns", "historical_dns", settings.historical_dns, "Historical DNS match"),
        (
            "certificate_match",
            "certificate_match",
            settings.certificate_match,
            "TLS certificate contains the target domain",
        ),
        ("favicon_match", "favicon_match", settings.favicon_match, "Matching favicon"),
        ("body_hash_match", "body_hash_match", settings.body_hash_match, "Matching body hash"),
        ("title_match", "title_match", settings.title_match, "Matching HTML title"),
        (
            "current_dns",
            "current_dns",
            settings.current_dns,
            "Current DNS alone may identify the CDN/WAF edge",
        ),
        (
            "unrelated_certificate",
            "unrelated_certificate",
            settings.unrelated_certificate,
            "Certificate is unrelated to the target",
        ),
    )
    for evidence_type, rule, points, reason in rules:
        if evidence_type in types:
            _add(contributions, rule=rule, points=points, reason=reason)
    if "discovered_hostname_dns" in types or any(candidate.hostnames):
        _add(
            contributions,
            rule="hostname_match",
            points=settings.hostname_match,
            reason="Related hostname resolves to candidate",
        )
    independent_sources = {
        item.source
        for item in candidate.evidence
        if item.source not in {"active_validation", "dns_enrichment"}
    }
    if len(independent_sources) >= 2:
        _add(
            contributions,
            rule="multi_source_bonus",
            points=settings.multi_source_bonus,
            reason=f"Seen in {len(independent_sources)} independent sources",
        )
    if candidate.cdn_provider:
        _add(
            contributions,
            rule="known_cdn_range",
            points=settings.known_cdn_range,
            reason=f"Associated with CDN/WAF provider {candidate.cdn_provider}",
        )
    if candidate.last_seen and current - candidate.last_seen > timedelta(days=365):
        _add(
            contributions,
            rule="stale_observation",
            points=settings.stale_observation,
            reason="Latest observation is older than one year",
        )
    candidate.scoring_reasons = contributions
    candidate.score = sum(item.points for item in contributions)
    candidate.confidence = classify(candidate, settings)
    return candidate


def classify(candidate: CandidateIP, settings: ScoringSettings) -> Confidence:
    """Classify using thresholds plus strict confirmation requirements."""
    if candidate.rejection_reasons:
        return Confidence.REJECTED
    sources = {
        item.source
        for item in candidate.evidence
        if item.source not in {"active_validation", "dns_enrichment"}
    }
    active_types = {item.type for item in candidate.evidence if item.source == "active_validation"}
    corroborating_active = active_types & {
        "body_hash_match",
        "favicon_match",
        "certificate_match",
    }
    if (
        candidate.score >= settings.confirmed_threshold
        and candidate.active_validation_performed
        and len(sources) >= 2
        and len(corroborating_active) >= 2
    ):
        return Confidence.CONFIRMED
    if candidate.score >= settings.high_threshold:
        return Confidence.HIGH
    if candidate.score >= settings.medium_threshold:
        return Confidence.MEDIUM
    if candidate.score >= settings.low_threshold:
        return Confidence.LOW
    return Confidence.UNKNOWN


def score_candidates(candidates: list[CandidateIP], settings: ScoringSettings) -> list[CandidateIP]:
    """Score and sort candidates descending, then by canonical IP."""
    scored = [score_candidate(candidate, settings) for candidate in candidates]
    return sorted(scored, key=lambda item: (-item.score, item.ip))
