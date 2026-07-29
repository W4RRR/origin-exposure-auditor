"""DNS enrichment of discovered, related hostnames."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from origin_audit.models import CandidateIP
from origin_audit.providers.base import candidate_from_ip
from origin_audit.utils.domains import is_related_hostname


async def resolve_related_hostnames(
    hostnames: list[str],
    domain: str,
    *,
    timeout_seconds: float,
    concurrency: int,
    limit: int = 200,
) -> list[CandidateIP]:
    """Resolve a bounded set of target-related hostnames."""
    semaphore = asyncio.Semaphore(concurrency)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout_seconds

    async def resolve_one(hostname: str) -> list[CandidateIP]:
        try:
            if not is_related_hostname(hostname, domain):
                return []
        except Exception:
            return []
        output: list[CandidateIP] = []
        async with semaphore:
            for record_type in ("A", "AAAA"):
                try:
                    answer = await resolver.resolve(hostname, record_type, search=False)
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                    dns.exception.Timeout,
                ):
                    continue
                for item in answer:
                    value = item.to_text()
                    candidate = candidate_from_ip(
                        "dns_enrichment",
                        value,
                        evidence_type="discovered_hostname_dns",
                        evidence_value=f"{hostname} {record_type} {value}",
                        hostname=hostname,
                    )
                    if candidate:
                        output.append(candidate)
        return output

    tasks = [resolve_one(hostname) for hostname in sorted(set(hostnames))[:limit]]
    results = await asyncio.gather(*tasks)
    return [candidate for group in results for candidate in group]
