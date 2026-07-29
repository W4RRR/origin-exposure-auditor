"""VirusTotal API v3 passive DNS provider."""

from __future__ import annotations

from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import (
    Provider,
    ProviderContext,
    candidate_from_ip,
    failed_result,
    parse_datetime,
)
from origin_audit.utils.timestamps import utc_now


class VirusTotalProvider(Provider):
    """Collect domain resolutions through the current VirusTotal v3 relationship."""

    name = "virustotal"
    required_environment = ("VIRUSTOTAL_API_KEY",)

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        headers = {"x-apikey": context.environment["VIRUSTOTAL_API_KEY"]}
        url = f"https://www.virustotal.com/api/v3/domains/{target.domain}/resolutions"
        candidates = []
        page = 0
        try:
            while url and page < context.config.provider(self.name).max_pages:
                data = await context.transport.get_json(
                    url,
                    params={"limit": 40} if page == 0 else None,
                    headers=headers,
                    cache_parameters={"domain": target.domain, "page": page},
                )
                if not isinstance(data, dict):
                    raise ValueError("Unexpected VirusTotal response shape")
                for item in data.get("data", []):
                    if not isinstance(item, dict):
                        continue
                    attributes = item.get("attributes", {})
                    if not isinstance(attributes, dict):
                        continue
                    value = attributes.get("ip_address")
                    if not isinstance(value, str):
                        continue
                    observed = parse_datetime(attributes.get("date"))
                    hostname = str(attributes.get("host_name") or target.domain)
                    candidate = candidate_from_ip(
                        self.name,
                        value,
                        evidence_type="historical_dns",
                        evidence_value=f"{hostname} resolved to {value}",
                        observed_at=observed,
                        hostname=hostname,
                        notes=str(attributes.get("resolver") or "VirusTotal"),
                    )
                    if candidate:
                        candidates.append(candidate)
                links = data.get("links", {})
                next_url = links.get("next") if isinstance(links, dict) else None
                url = str(next_url) if next_url else ""
                page += 1
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            message=f"{len(candidates)} resolution observations",
            finished_at=utc_now(),
        )
