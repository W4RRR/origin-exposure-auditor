"""Optional ViewDNS contracted API provider."""

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


class ViewDNSProvider(Provider):
    """Use ViewDNS IP History only when the user supplies an API key."""

    name = "viewdns"
    required_environment = ("VIEWDNS_API_KEY",)

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        candidates = []
        try:
            data = await context.transport.get_json(
                "https://api.viewdns.info/iphistory/",
                params={
                    "domain": target.domain,
                    "apikey": context.environment["VIEWDNS_API_KEY"],
                    "output": "json",
                },
                cache_parameters={"domain": target.domain},
            )
            if not isinstance(data, dict):
                raise ValueError("Unexpected ViewDNS response shape")
            response = data.get("response", {})
            records = response.get("records", []) if isinstance(response, dict) else []
            for record in records:
                if not isinstance(record, dict) or not isinstance(record.get("ip"), str):
                    continue
                candidate = candidate_from_ip(
                    self.name,
                    record["ip"],
                    evidence_type="historical_dns",
                    evidence_value=f"{target.domain} previously used {record['ip']}",
                    observed_at=parse_datetime(record.get("lastseen")),
                    hostname=target.domain,
                    organization=str(record["owner"]) if record.get("owner") else None,
                    country=str(record["location"]) if record.get("location") else None,
                )
                if candidate:
                    candidates.append(candidate)
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(provider=self.name, candidates=candidates, finished_at=utc_now())
