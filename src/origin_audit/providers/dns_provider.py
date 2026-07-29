"""Current DNS provider."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver

from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import Provider, ProviderContext, candidate_from_ip
from origin_audit.utils.timestamps import utc_now

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DNSProvider(Provider):
    """Resolve standard current DNS records using dnspython."""

    name = "dns"

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = context.config.timeout_seconds
        records: dict[str, list[str]] = {}
        candidates = []
        errors: list[str] = []
        for record_type in _RECORD_TYPES:
            try:
                answer = await resolver.resolve(target.domain, record_type, search=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                records[record_type] = []
                continue
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                errors.append(f"{record_type}: {type(exc).__name__}")
                records[record_type] = []
                continue
            values = [item.to_text().strip('"') for item in answer]
            records[record_type] = values
            if record_type in {"A", "AAAA"}:
                for value in values:
                    candidate = candidate_from_ip(
                        self.name,
                        value,
                        evidence_type="current_dns",
                        evidence_value=f"{target.domain} {record_type} {value}",
                        hostname=target.domain,
                    )
                    if candidate:
                        candidates.append(candidate)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            records=records,
            errors=errors,
            finished_at=utc_now(),
        )
