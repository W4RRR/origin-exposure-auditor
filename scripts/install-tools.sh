#!/usr/bin/env bash
set -eu

echo "origin-audit has Python fallbacks for core functionality."
echo "Optional tools are never installed automatically."

if command -v wafw00f >/dev/null 2>&1; then
  wafw00f --version || true
else
  echo "Optional wafw00f: install in an isolated environment with 'pipx install wafw00f'."
fi

if command -v httpx >/dev/null 2>&1; then
  httpx -version || true
else
  echo "Optional ProjectDiscovery httpx is not installed."
  echo "Follow the vendor's signed-release or Go installation instructions."
fi
