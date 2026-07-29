"""TLS handshakes with certificate extraction."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import UTC, datetime

from origin_audit.models import CertificateEvidence
from origin_audit.utils.ips import is_public_ip


def _flatten_name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    values = [value for group in parts for key, value in group if key]
    return ", ".join(values) if values else None


def _parse_cert(cert: dict[str, object], der: bytes, source: str) -> CertificateEvidence:
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    common_name: str | None = None
    if isinstance(subject, tuple):
        for group in subject:
            for key, value in group:
                if key == "commonName":
                    common_name = value
    san_values = cert.get("subjectAltName", ())
    san = (
        [value for kind, value in san_values if kind == "DNS"]
        if isinstance(san_values, tuple)
        else []
    )

    def parse_ssl_date(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
        except (ValueError, OverflowError):
            return None

    return CertificateEvidence(
        source=source,
        common_name=common_name,
        san=san,
        issuer=_flatten_name(issuer) if isinstance(issuer, tuple) else None,
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        not_before=parse_ssl_date(cert.get("notBefore")),
        not_after=parse_ssl_date(cert.get("notAfter")),
    )


async def fetch_certificate(
    connect_host: str,
    *,
    server_name: str,
    port: int = 443,
    timeout_seconds: float = 10.0,
    source: str = "tls",
) -> CertificateEvidence:
    """Perform a verifying TLS handshake and return bounded certificate metadata."""
    if _looks_like_ip(connect_host) and not is_public_ip(connect_host):
        raise ValueError("TLS connection to non-public IP is blocked")
    context = ssl.create_default_context()
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            connect_host,
            port,
            ssl=context,
            server_hostname=server_name,
        ),
        timeout=timeout_seconds,
    )
    del reader
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            raise ValueError("TLS negotiation did not produce an SSL object")
        cert = ssl_object.getpeercert()
        der = ssl_object.getpeercert(binary_form=True)
        if not isinstance(cert, dict) or not der:
            raise ValueError("Peer certificate was unavailable")
        return _parse_cert(cert, der, source)
    finally:
        writer.close()
        await writer.wait_closed()


def _looks_like_ip(value: str) -> bool:
    try:
        is_public_ip(value)
    except Exception:
        return False
    return True
