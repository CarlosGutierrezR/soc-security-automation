import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.virustotal_client import VirusTotalClient  # noqa: E402


def test_vt_ipv4_lookup_dry_run():
    client = VirusTotalClient(dry_run=True)

    result = client.lookup_ipv4("8.8.8.8")

    assert result == {
        "status": "dry_run",
        "request": {
            "method": "GET",
            "url": ("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"),
        },
    }


def test_vt_domain_lookup_dry_run():
    client = VirusTotalClient(dry_run=True)

    result = client.lookup_domain("example.com")

    assert result["status"] == "dry_run"
    assert result["request"]["url"].endswith("/domains/example.com")


def test_vt_sha256_lookup_dry_run():
    sha256 = "a" * 64
    client = VirusTotalClient(dry_run=True)

    result = client.lookup_sha256(sha256)

    assert result["status"] == "dry_run"
    assert result["request"]["url"].endswith(f"/files/{sha256}")


def test_vt_live_request_requires_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    client = VirusTotalClient(
        api_key=None,
        dry_run=False,
    )

    with pytest.raises(ValueError):
        client.lookup_domain("example.com")


def test_vt_live_request_uses_api_key_and_timeout(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "type": "domain",
                    "id": "example.com",
                }
            }

    def fake_get(url, headers, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout

        return FakeResponse()

    monkeypatch.setattr(
        "soc_automation.virustotal_client.requests.get",
        fake_get,
    )

    client = VirusTotalClient(
        api_key="test-api-key",
        timeout=7,
        dry_run=False,
    )

    result = client.lookup_domain("example.com")

    assert captured["url"] == ("https://www.virustotal.com/api/v3/domains/example.com")
    assert captured["headers"]["x-apikey"] == "test-api-key"
    assert captured["headers"]["accept"] == "application/json"
    assert captured["timeout"] == 7

    assert result["data"]["id"] == "example.com"


def test_vt_live_request_propagates_http_error(monkeypatch):
    import requests

    class FakeResponse:
        def raise_for_status(self):
            raise requests.HTTPError("429 Too Many Requests")

        def json(self):
            return {}

    def fake_get(url, headers, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "soc_automation.virustotal_client.requests.get",
        fake_get,
    )

    client = VirusTotalClient(
        api_key="test-api-key",
        dry_run=False,
    )

    with pytest.raises(requests.HTTPError):
        client.lookup_domain("example.com")
