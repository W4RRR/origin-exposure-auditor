"""Public Certificate Transparency hostname discovery."""

from __future__ import annotations

from typing import Any

from origin_audit.exceptions import ConfigurationError
from origin_audit.models import ProviderResult, Target
from origin_audit.providers.base import Provider, ProviderContext, failed_result
from origin_audit.utils.domains import is_related_hostname
from origin_audit.utils.timestamps import utc_now


class CertificateTransparencyProvider(Provider):
    """Query crt.sh's public JSON view without browser automation."""

    name = "ct"

    async def collect(self, target: Target, context: ProviderContext) -> ProviderResult:
        try:
            data = await context.transport.get_json(
                "https://crt.sh/",
                params={"q": f"%.{target.domain}", "output": "json"},
                cache_parameters={"domain": target.domain},
            )
        except Exception as exc:
            return failed_result(self.name, exc)
        if not isinstance(data, list):
            return failed_result(self.name, ValueError("Unexpected Certificate Transparency shape"))
        hostnames: set[str] = {target.domain}
        for row in data:
            if not isinstance(row, dict):
                continue
            names = str(row.get("name_value", "")).splitlines()
            for raw_name in names:
                cleaned = raw_name.removeprefix("*.").strip().lower().rstrip(".")
                try:
                    if cleaned and is_related_hostname(cleaned, target.domain):
                        hostnames.add(cleaned)
                except ConfigurationError:
                    continue
        raw_export: dict[str, Any] | None = None
        if context.save_raw_responses:
            raw_export = {"row_count": len(data)}
        return ProviderResult(
            provider=self.name,
            hostnames=sorted(hostnames),
            message=f"{len(hostnames)} related hostnames found",
            raw=raw_export,
            finished_at=utc_now(),
        )
