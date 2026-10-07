import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.enrichment import (  # noqa: E402
    enrich_ioc,
    enrich_iocs,
    enrich_ipv4,
)


def test_enrich_ipv4_documentation_address():
    result = enrich_ipv4("192.0.2.22")

    assert result == {
        "type": "ipv4",
        "value": "192.0.2.22",
        "scope": "documentation",
        "external_lookup": False,
    }


def test_enrich_ipv4_private_address():
    result = enrich_ipv4("10.50.20.22")

    assert result["scope"] == "private"
    assert result["external_lookup"] is False


def test_enrich_ipv4_public_address():
    result = enrich_ipv4("8.8.8.8")

    assert result["scope"] == "public"
    assert result["external_lookup"] is True


def test_enrich_ipv4_rejects_invalid_address():
    with pytest.raises(ValueError):
        enrich_ipv4("999.999.999.999")


def test_enrich_ioc_ipv4_uses_local_classification():
    ioc = {
        "type": "ipv4",
        "value": "192.0.2.22",
    }

    result = enrich_ioc(ioc)

    assert result == {
        "type": "ipv4",
        "value": "192.0.2.22",
        "scope": "documentation",
        "external_lookup": False,
        "enrichment_status": "local",
    }


def test_enrich_ioc_sha256_marks_external_lookup_pending():
    ioc = {
        "type": "sha256",
        "value": "a" * 64,
    }

    result = enrich_ioc(ioc)

    assert result["enrichment_status"] == "pending_external"
    assert result["external_lookup"] is True


def test_enrich_ioc_domain_marks_external_lookup_pending():
    ioc = {
        "type": "domain",
        "value": "example.com",
    }

    result = enrich_ioc(ioc)

    assert result["enrichment_status"] == "pending_external"
    assert result["external_lookup"] is True


def test_enrich_iocs_processes_mixed_ioc_list():
    iocs = [
        {
            "type": "ipv4",
            "value": "192.0.2.22",
        },
        {
            "type": "domain",
            "value": "example.com",
        },
    ]

    result = enrich_iocs(iocs)

    assert len(result) == 2
    assert result[0]["external_lookup"] is False
    assert result[1]["external_lookup"] is True
