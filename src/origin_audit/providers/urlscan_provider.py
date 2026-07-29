"""urlscan.io historical search provider."""

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


class URLScanProvider(Provider):
    """Search existing urlscan.io results; never submits from ``collect``."""

    name = "urlscan"

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        headers: dict[str, str] = {}
        if key := context.environment.get("URLSCAN_API_KEY"):
            headers["api-key"] = key
        candidates = []
        try:
            data = await context.transport.get_json(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.domain:{target.domain}", "size": 100},
                headers=headers,
                cache_parameters={"domain": target.domain, "page": 0},
            )
            if not isinstance(data, dict):
                raise ValueError("Unexpected urlscan response shape")
            for item in data.get("results", []):
                if not isinstance(item, dict):
                    continue
                page = item.get("page", {})
                task = item.get("task", {})
                if not isinstance(page, dict) or not isinstance(task, dict):
                    continue
                value = page.get("ip")
                if not isinstance(value, str):
                    continue
                observed = parse_datetime(task.get("time"))
                asn_value = page.get("asn")
                asn = (
                    f"AS{asn_value}" if asn_value and not str(asn_value).startswith("AS") else None
                )
                candidate = candidate_from_ip(
                    self.name,
                    value,
                    evidence_type="archived_scan",
                    evidence_value=str(task.get("url") or page.get("url") or target.domain),
                    observed_at=observed,
                    hostname=str(page.get("domain") or target.domain),
                    asn=asn,
                    organization=str(page.get("asnname")) if page.get("asnname") else None,
                )
                if candidate:
                    candidates.append(candidate)
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            message="Existing results only; no scan was submitted",
            finished_at=utc_now(),
        )

    async def submit(
        self,
        target: Target,
        context: ProviderContext,
        *,
        visibility: str,
    ) -> dict[str, object]:
        """Submit one explicitly authorized scan after CLI confirmation."""
        key = context.environment.get("URLSCAN_API_KEY")
        if not key:
            raise ValueError("URLSCAN_API_KEY is required to submit a scan")
        if visibility not in {"public", "unlisted", "private"}:
            raise ValueError("Visibility must be public, unlisted, or private")
        data = await context.transport.post_json(
            "https://urlscan.io/api/v1/scan/",
            payload={"url": f"https://{target.domain}/", "visibility": visibility},
            headers={"api-key": key, "content-type": "application/json"},
            cacheable=False,
        )
        if not isinstance(data, dict):
            raise ValueError("Unexpected urlscan submission response")
        return data
