"""Optional FOFA API provider."""

from __future__ import annotations

import base64

from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import Provider, ProviderContext, candidate_from_ip, failed_result
from origin_audit.utils.timestamps import utc_now


class FOFAProvider(Provider):
    """Search FOFA's documented API without making it a core dependency."""

    name = "fofa"
    required_environment = ("FOFA_EMAIL", "FOFA_API_KEY")

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        query = f'domain="{target.domain}"'
        encoded = base64.b64encode(query.encode()).decode()
        fields = ["ip", "port", "host", "domain", "title", "cert", "asn", "org", "lastupdatetime"]
        candidates = []
        try:
            data = await context.transport.get_json(
                "https://fofa.info/api/v1/search/all",
                params={
                    "email": context.environment["FOFA_EMAIL"],
                    "key": context.environment["FOFA_API_KEY"],
                    "qbase64": encoded,
                    "fields": ",".join(fields),
                    "size": 100,
                },
                cache_parameters={"domain": target.domain, "query": query},
            )
            if not isinstance(data, dict):
                raise ValueError("Unexpected FOFA response shape")
            if data.get("error"):
                raise ValueError(str(data.get("errmsg") or "FOFA returned an error"))
            for row in data.get("results", []):
                if not isinstance(row, list) or len(row) < 2:
                    continue
                values = dict(zip(fields, row, strict=False))
                if not isinstance(values.get("ip"), str):
                    continue
                port = values.get("port")
                candidate = candidate_from_ip(
                    self.name,
                    values["ip"],
                    evidence_type="indexed_asset",
                    evidence_value=str(values.get("host") or values.get("domain") or target.domain),
                    hostname=str(values.get("domain") or target.domain),
                    ports=[int(str(port))] if port is not None and str(port).isdigit() else [],
                    asn=str(values["asn"]) if values.get("asn") else None,
                    organization=str(values["org"]) if values.get("org") else None,
                )
                if candidate:
                    candidates.append(candidate)
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(provider=self.name, candidates=candidates, finished_at=utc_now())
