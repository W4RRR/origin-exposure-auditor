"""Provider registry."""

from origin_audit.providers.base import Provider
from origin_audit.providers.censys_provider import CensysProvider
from origin_audit.providers.certificate_transparency import CertificateTransparencyProvider
from origin_audit.providers.dns_provider import DNSProvider
from origin_audit.providers.fofa_provider import FOFAProvider
from origin_audit.providers.otx_provider import OTXProvider
from origin_audit.providers.securitytrails_provider import SecurityTrailsProvider
from origin_audit.providers.shodan_provider import ShodanProvider
from origin_audit.providers.urlscan_provider import URLScanProvider
from origin_audit.providers.viewdns_provider import ViewDNSProvider
from origin_audit.providers.virustotal_provider import VirusTotalProvider


def provider_registry() -> dict[str, Provider]:
    """Return fresh provider instances keyed by CLI name."""
    providers: list[Provider] = [
        DNSProvider(),
        CertificateTransparencyProvider(),
        OTXProvider(),
        URLScanProvider(),
        ShodanProvider(),
        CensysProvider(),
        VirusTotalProvider(),
        SecurityTrailsProvider(),
        FOFAProvider(),
        ViewDNSProvider(),
    ]
    return {provider.name: provider for provider in providers}


__all__ = ["Provider", "provider_registry"]
