"""Shodan passive search provider."""

from __future__ import annotations

from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import Provider, ProviderContext, candidate_from_ip, failed_result
from origin_audit.utils.timestamps import utc_now


class ShodanProvider(Provider):
    """Search Shodan's indexed banners without requesting a new scan."""

    name = "shodan"
    required_environment = ("SHODAN_API_KEY",)

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        if not await self.is_available(context):
            return self.unavailable_result()
        settings = context.config.provider(self.name)
        template = settings.query_template or 'ssl:"{domain}"'
        query = template.format(domain=target.domain)
        candidates = []
        try:
            for page in range(1, settings.max_pages + 1):
                data = await context.transport.get_json(
                    "https://api.shodan.io/shodan/host/search",
                    params={
                        "key": context.environment["SHODAN_API_KEY"],
                        "query": query,
                        "page": page,
                        "minify": "false",
                    },
                    cache_parameters={"domain": target.domain, "query": query, "page": page},
                )
                if not isinstance(data, dict):
                    raise ValueError("Unexpected Shodan response shape")
                matches = data.get("matches", [])
                if not matches:
                    break
                for item in matches:
                    if not isinstance(item, dict) or not isinstance(item.get("ip_str"), str):
                        continue
                    hostnames = item.get("hostnames") or item.get("domains") or []
                    hostname = str(hostnames[0]) if hostnames else target.domain
                    port = item.get("port")
                    candidate = candidate_from_ip(
                        self.name,
                        item["ip_str"],
                        evidence_type="indexed_certificate_or_hostname",
                        evidence_value=f"Shodan query matched {query}",
                        hostname=hostname,
                        ports=[int(port)] if isinstance(port, int) else [],
                        asn=str(item["asn"]) if item.get("asn") else None,
                        organization=str(item["org"]) if item.get("org") else None,
                        country=str(item.get("location", {}).get("country_code"))
                        if isinstance(item.get("location"), dict)
                        and item.get("location", {}).get("country_code")
                        else None,
                    )
                    if candidate:
                        candidates.append(candidate)
        except Exception as exc:
            return failed_result(self.name, exc)
        return ProviderResult(
            provider=self.name,
            candidates=candidates,
            message=f"Query template: {template}",
            finished_at=utc_now(),
        )
