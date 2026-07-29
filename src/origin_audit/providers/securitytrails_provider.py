"""SecurityTrails historical DNS provider."""

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


class SecurityTrailsProvider(Provider):
    """Collect historical A and AAAA records from the documented API."""

    name = "securitytrails"
    required_environment = ("SECURITYTRAILS_API_KEY",)

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        headers = {"APIKEY": context.environment["SECURITYTRAILS_API_KEY"]}
        candidates = []
        try:
            for record_type in ("a", "aaaa"):
                data = await context.transport.get_json(
                    f"https://api.securitytrails.com/v1/history/{target.domain}/dns/{record_type}",
                    headers=headers,
                    cache_parameters={"domain": target.domain, "type": record_type},
                )
                if not isinstance(data, dict):
                    continue
                for record in data.get("records", []):
                    if not isinstance(record, dict):
                        continue
                    seen = parse_datetime(record.get("last_seen"))
                    values = record.get("values", [])
                    for item in values:
                        value = item.get("ip") if isinstance(item, dict) else None
                        if not isinstance(value, str):
                            continue
                        candidate = candidate_from_ip(
                            self.name,
                            value,
                            evidence_type="historical_dns",
                            evidence_value=f"{target.domain} {record_type.upper()} {value}",
                            observed_at=seen,
                            hostname=target.domain,
                        )
                        if candidate:
                            candidates.append(candidate)
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            finished_at=utc_now(),
        )
