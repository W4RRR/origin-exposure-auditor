"""Candidate merging without loss of provenance."""

from datetime import datetime

from origin_audit.models import CandidateIP


def _unique[T](left: list[T], right: list[T]) -> list[T]:
    output = list(left)
    for item in right:
        if item not in output:
            output.append(item)
    return output


def _earliest(left: datetime | None, right: datetime | None) -> datetime | None:
    values = [value for value in (left, right) if value is not None]
    return min(values) if values else None


def _latest(left: datetime | None, right: datetime | None) -> datetime | None:
    values = [value for value in (left, right) if value is not None]
    return max(values) if values else None


def merge_candidate(base: CandidateIP, incoming: CandidateIP) -> CandidateIP:
    """Merge one candidate into another candidate with the same IP."""
    if base.ip != incoming.ip:
        raise ValueError("Cannot merge candidates with different IP addresses")
    base.sources = _unique(base.sources, incoming.sources)
    base.hostnames = _unique(base.hostnames, incoming.hostnames)
    base.ports = sorted(set(base.ports) | set(incoming.ports))
    base.certificates = _unique(base.certificates, incoming.certificates)
    base.http_observations = _unique(base.http_observations, incoming.http_observations)
    base.favicon_hashes = _unique(base.favicon_hashes, incoming.favicon_hashes)
    base.evidence = _unique(base.evidence, incoming.evidence)
    base.rejection_reasons = _unique(base.rejection_reasons, incoming.rejection_reasons)
    base.first_seen = _earliest(base.first_seen, incoming.first_seen)
    base.last_seen = _latest(base.last_seen, incoming.last_seen)
    for field in ("asn", "organization", "country", "cloud_provider", "cdn_provider"):
        if getattr(base, field) is None:
            setattr(base, field, getattr(incoming, field))
    base.active_validation_performed |= incoming.active_validation_performed
    return base


def deduplicate_candidates(candidates: list[CandidateIP]) -> list[CandidateIP]:
    """Deduplicate candidates by normalized address while preserving evidence."""
    merged: dict[str, CandidateIP] = {}
    for candidate in candidates:
        if candidate.ip in merged:
            merge_candidate(merged[candidate.ip], candidate)
        else:
            merged[candidate.ip] = candidate.model_copy(deep=True)
    return list(merged.values())
