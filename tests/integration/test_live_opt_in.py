"""Opt-in integration guard."""

import os

import pytest


@pytest.mark.integration
def test_integration_environment_is_explicit() -> None:
    if os.environ.get("ORIGIN_AUDIT_RUN_INTEGRATION") != "1":
        pytest.skip("Set ORIGIN_AUDIT_RUN_INTEGRATION=1 for authorized lab tests")
    domain = os.environ.get("ORIGIN_AUDIT_LAB_DOMAIN")
    assert domain, "ORIGIN_AUDIT_LAB_DOMAIN must name an authorized laboratory domain"
