"""Bounded favicon discovery and hashing."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from origin_audit.models import FaviconEvidence
from origin_audit.utils.hashing import md5_hex, sha256_hex, shodan_mmh3


class _IconParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "link":
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if "icon" in values.get("rel", "").lower() and values.get("href"):
            self.urls.append(values["href"])


def discover_icon_urls(page_url: str, body: bytes) -> list[str]:
    """Return same-origin icon candidates, always including ``/favicon.ico``."""
    parser = _IconParser()
    parser.feed(body[:256_000].decode("utf-8", errors="replace"))
    page = urlparse(page_url)
    output = [urljoin(page_url, "/favicon.ico")]
    for item in parser.urls:
        candidate = urljoin(page_url, item)
        parsed = urlparse(candidate)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname == page.hostname
            and candidate not in output
        ):
            output.append(candidate)
    return output[:5]


async def fetch_favicon(
    client: httpx.AsyncClient,
    urls: list[str],
    *,
    maximum_bytes: int = 384_000,
    host_header: str | None = None,
    sni_hostname: str | None = None,
) -> FaviconEvidence | None:
    """Fetch the first valid, bounded favicon without cross-origin redirects."""
    for url in urls:
        parsed = urlparse(url)
        headers = {"Host": host_header} if host_header else None
        extensions = {"sni_hostname": sni_hostname} if sni_hostname else None
        request = client.build_request("GET", url, headers=headers, extensions=extensions)
        response: httpx.Response | None = None
        try:
            response = await client.send(request, stream=True, follow_redirects=False)
            if response.status_code != 200:
                continue
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > maximum_bytes:
                continue
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > maximum_bytes:
                    data.clear()
                    break
            if not data:
                continue
            payload = bytes(data)
            return FaviconEvidence(
                source_url=url,
                md5=md5_hex(payload),
                sha256=sha256_hex(payload),
                mmh3=shodan_mmh3(payload),
                size=len(payload),
            )
        except httpx.HTTPError:
            continue
        finally:
            if response is not None:
                await response.aclose()
        if parsed.hostname is None:
            break
    return None
