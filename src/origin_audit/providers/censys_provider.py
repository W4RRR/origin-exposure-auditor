"""Censys Platform API v3 provider."""

from __future__ import annotations

from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import Provider, ProviderContext, candidate_from_ip, failed_result
from origin_audit.utils.timestamps import utc_now


class CensysProvider(Provider):
    """Search current Censys Platform data using PAT authentication."""

    name = "censys"
    required_environment = ("CENSYS_API_TOKEN",)

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        settings = context.config.provider(self.name)
        template = settings.query_template or 'host.services.cert.names = "{domain}"'
        query = template.format(domain=target.domain)
        token: str | None = None
        candidates = []
        headers = {
            "Authorization": f"Bearer {context.environment['CENSYS_API_TOKEN']}",
            "Accept": "application/json",
        }
        organization = context.environment.get("CENSYS_ORGANIZATION_ID")
        try:
            for page in range(settings.max_pages):
                payload: dict[str, object] = {
                    "query": query,
                    "page_size": 100,
                    "fields": [
                        "host.ip",
                        "host.autonomous_system.name",
                        "host.autonomous_system.asn",
                        "host.location.country",
                        "host.services.port",
                        "host.services.transport_protocol",
                        "host.services.protocol",
                    ],
                }
                if token:
                    payload["page_token"] = token
                params = {"organization_id": organization} if organization else None
                data = await context.transport.post_json(
                    "https://api.platform.censys.io/v3/global/search/query"
                    + (f"?organization_id={organization}" if params else ""),
                    payload=payload,
                    headers=headers,
                    cache_parameters={"domain": target.domain, "query": query, "page": page},
                )
                if not isinstance(data, dict):
                    raise ValueError("Unexpected Censys response shape")
                result = data.get("result", data)
                if not isinstance(result, dict):
                    break
                hits = result.get("hits", [])
                for hit in hits:
                    if not isinstance(hit, dict):
                        continue
                    host = hit.get("host", hit)
                    if not isinstance(host, dict) or not isinstance(host.get("ip"), str):
                        continue
                    services = hit.get("matched_services") or host.get("services") or []
                    ports = [
                        int(service["port"])
                        for service in services
                        if isinstance(service, dict) and isinstance(service.get("port"), int)
                    ]
                    autonomous = host.get("autonomous_system", {})
                    location = host.get("location", {})
                    asn_value = autonomous.get("asn") if isinstance(autonomous, dict) else None
                    candidate = candidate_from_ip(
                        self.name,
                        host["ip"],
                        evidence_type="indexed_certificate",
                        evidence_value=f"Censys CenQL matched {target.domain}",
                        hostname=target.domain,
                        ports=ports,
                        asn=f"AS{asn_value}" if asn_value else None,
                        organization=str(autonomous.get("name"))
                        if isinstance(autonomous, dict) and autonomous.get("name")
                        else None,
                        country=str(location.get("country"))
                        if isinstance(location, dict) and location.get("country")
                        else None,
                    )
                    if candidate:
                        candidates.append(candidate)
                token_value = result.get("next_page_token") or result.get("page_token")
                token = str(token_value) if token_value else None
                if not token:
                    break
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            message="Censys Platform API v3",
            finished_at=utc_now(),
        )
