"""Safe HTTP observations and direct candidate validation."""

from __future__ import annotations

import re
from time import monotonic
from urllib.parse import urljoin, urlparse

import httpx

from origin_audit.models import HttpObservation
from origin_audit.utils.hashing import normalize_body, sha256_hex
from origin_audit.utils.ips import is_public_ip

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title\s*>", re.I | re.S)
_SPACE = re.compile(r"\s+")


def extract_title(body: bytes) -> str | None:
    """Extract a bounded, normalized HTML title."""
    match = _TITLE.search(body[:256_000])
    if not match:
        return None
    value = match.group(1).decode("utf-8", errors="replace")
    return _SPACE.sub(" ", value).strip()[:300] or None


def detect_technologies(headers: httpx.Headers, body: bytes) -> list[str]:
    """Make conservative passive technology observations."""
    output: set[str] = set()
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()
    sample = body[:128_000].lower()
    markers = {
        "nginx": b"nginx",
        "apache": b"apache",
        "wordpress": b"wp-content",
        "drupal": b"drupal",
        "django": b"csrfmiddlewaretoken",
    }
    for name, marker in markers.items():
        if marker in sample or name in server or name in powered:
            output.add(name)
    return sorted(output)


def bounded_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Retain useful passive headers without storing cookie values."""
    output: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        allowed = lowered in {
            "server",
            "content-type",
            "location",
            "via",
            "set-cookie",
        } or lowered.startswith(("x-", "cf-", "akamai-"))
        if not allowed:
            continue
        if lowered == "set-cookie":
            cookie_names = [
                item.split("=", 1)[0].strip()
                for item in headers.get_list("set-cookie")
                if "=" in item
            ]
            value = "; ".join(cookie_names)
        output[lowered] = value[:500]
    return output


async def read_limited(response: httpx.Response, maximum: int) -> bytes:
    """Read at most ``maximum`` response bytes."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > maximum:
            remaining = maximum - (total - len(chunk))
            if remaining > 0:
                chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
    return b"".join(chunks)


async def probe(
    client: httpx.AsyncClient,
    *,
    url: str,
    maximum_bytes: int,
    host_header: str | None = None,
    sni_hostname: str | None = None,
) -> tuple[HttpObservation, bytes]:
    """Perform one GET request without following redirects."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS are supported")
    if _is_ip(parsed.hostname or "") and not is_public_ip(parsed.hostname or ""):
        raise ValueError("HTTP connection to non-public IP is blocked")
    headers = {"Host": host_header} if host_header else None
    extensions = {"sni_hostname": sni_hostname} if sni_hostname else None
    started = monotonic()
    request = client.build_request("GET", url, headers=headers, extensions=extensions)
    response: httpx.Response | None = None
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
        body = await read_limited(response, maximum_bytes)
        elapsed = (monotonic() - started) * 1000
        location = response.headers.get("location")
        final_url = urljoin(url, location) if location else str(response.url)
        observation = HttpObservation(
            url=url,
            status_code=response.status_code,
            title=extract_title(body),
            server=response.headers.get("server"),
            content_type=response.headers.get("content-type"),
            body_length=len(body),
            final_url=final_url,
            response_headers=bounded_response_headers(response.headers),
            body_sha256=sha256_hex(normalize_body(body)),
            elapsed_ms=round(elapsed, 2),
            technologies=detect_technologies(response.headers, body),
        )
        return observation, body
    except httpx.HTTPError as exc:
        return HttpObservation(url=url, error=f"{type(exc).__name__}: {exc}"), b""
    finally:
        if response is not None:
            await response.aclose()


def _is_ip(value: str) -> bool:
    try:
        is_public_ip(value)
    except Exception:
        return False
    return True
