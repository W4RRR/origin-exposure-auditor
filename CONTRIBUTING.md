# Contributing

Contributions must keep the project defensive and authorization-first.

1. Create an isolated Python 3.12 environment.
2. Install `python -m pip install -e ".[dev]"`.
3. Add tests with mocked provider responses.
4. Run `pytest`, `ruff check .`, `ruff format --check .`, `mypy src`, and
   `bandit -c pyproject.toml -r src`.
5. Update the changelog and provider documentation when behavior changes.

Do not contribute exploit payloads, authentication bypasses, port or directory
scanners, credential handling, WAF evasion techniques, scraping that violates terms,
real API responses, production domains, or non-documentation IP addresses.

New providers must use an official/contracted API, finite pagination, bounded responses,
rate limiting, redacted errors, optional credentials, and typed evidence. Tests may use
only `example.com`, `example.org`, `example.net`, and the documentation networks
`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
