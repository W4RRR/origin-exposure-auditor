"""Hashing helpers for bodies and favicons."""

import base64
import hashlib
import re

import mmh3

_WHITESPACE = re.compile(rb"\s+")


def normalize_body(body: bytes) -> bytes:
    """Normalize insignificant whitespace before content comparison."""
    return _WHITESPACE.sub(b" ", body).strip()


def sha256_hex(data: bytes) -> str:
    """Return a SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def md5_hex(data: bytes) -> str:
    """Return an MD5 digest for non-security favicon compatibility."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def shodan_mmh3(data: bytes) -> int:
    """Return Shodan-compatible signed MurmurHash3 over base64 favicon bytes."""
    encoded = base64.encodebytes(data)
    return int(mmh3.hash(encoded))
