"""AlienVault OTX passive provider."""

from __future__ import annotations

from origin_audit.models import ProviderResult, ProviderState, Target
from origin_audit.providers.base import (
    Provider,
    ProviderContext,
    candidate_from_ip,
    parse_datetime,
)
from origin_audit.utils.timestamps import utc_now


class OTXProvider(Provider):
    """Collect OTX passive DNS and observed URL IPs; key is optional."""

    name = "otx"

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        headers: dict[str, str] = {}
        if key := context.environment.get("OTX_API_KEY"):
            headers["X-OTX-API-KEY"] = key
        base = f"https://otx.alienvault.com/api/v1/indicator/hostname/{target.domain}"
        candidates = []
        errors: list[str] = []
        try:
            passive = await context.transport.get_json(
                f"{base}/passive_dns",
                headers=headers,
                cache_parameters={"domain": target.domain, "section": "passive_dns"},
            )
            if isinstance(passive, dict):
                for item in passive.get("passive_dns", []):
                    if not isinstance(item, dict) or not isinstance(item.get("address"), str):
                        continue
                    candidate = candidate_from_ip(
                        self.name,
                        item["address"],
                        evidence_type="passive_dns",
                        evidence_value=f"{item.get('hostname', target.domain)} A {item['address']}",
                        observed_at=parse_datetime(item.get("last")),
                        hostname=str(item.get("hostname") or target.domain),
                        asn=str(item["asn"]) if item.get("asn") else None,
                    )
                    if candidate:
                        candidates.append(candidate)
        except Exception as exc:
            errors.append(f"passive_dns: {exc}")
        try:
            urls = await context.transport.get_json(
                f"{base}/url_list",
                params={"limit": 100, "page": 1},
                headers=headers,
                cache_parameters={"domain": target.domain, "section": "url_list", "page": 1},
            )
            if isinstance(urls, dict):
                for item in urls.get("url_list", []):
                    if not isinstance(item, dict):
                        continue
                    result = item.get("result", {})
                    worker = result.get("urlworker", {}) if isinstance(result, dict) else {}
                    value = worker.get("ip") if isinstance(worker, dict) else None
                    if not isinstance(value, str):
                        continue
                    candidate = candidate_from_ip(
                        self.name,
                        value,
                        evidence_type="observed_url",
                        evidence_value=str(item.get("url") or target.domain),
                        observed_at=parse_datetime(item.get("date")),
                        hostname=str(item.get("hostname") or target.domain),
                    )
                    if candidate:
                        candidates.append(candidate)
        except Exception as exc:
            errors.append(f"url_list: {exc}")
        state = ProviderState.FAILED if errors and not candidates else ProviderState.OK
        return ProviderResult(
            provider=self.name,
            state=state,
            candidates=candidates,
            errors=errors,
            finished_at=utc_now(),
        )
