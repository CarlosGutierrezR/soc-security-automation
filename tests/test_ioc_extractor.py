import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.ioc_extractor import (  # noqa: E402
    extract_domains,
    extract_iocs,
    extract_iocs_from_alert,
    extract_ipv4,
    extract_sha256,
)


def test_extract_sha256():
    text = (
        "Hashes: "
        "SHA256=97AC98B1A92C286054CCE55239CFCCDFC"
        "23A5517BD07FE693072C9CA96C7DABB"
    )

    result = extract_sha256(text)

    assert result == [
        {
            "type": "sha256",
            "value": (
                "97ac98b1a92c286054cce55239cfccdfc"
                "23a5517bd07fe693072c9ca96c7dabb"
            ),
        }
    ]


def test_extract_sha256_returns_empty_list_when_absent():
    assert extract_sha256("cmd.exe started successfully") == []


def test_extract_ipv4():
    text = "Connection observed from 192.0.2.22 to 198.51.100.40"

    result = extract_ipv4(text)

    assert result == [
        {
            "type": "ipv4",
            "value": "192.0.2.22",
        },
        {
            "type": "ipv4",
            "value": "198.51.100.40",
        },
    ]


def test_extract_ipv4_rejects_invalid_address():
    text = "Invalid candidate 999.999.999.999"

    assert extract_ipv4(text) == []


def test_extract_domains():
    text = "Requests observed for example.com and api.example.org"

    result = extract_domains(text)

    assert result == [
        {
            "type": "domain",
            "value": "example.com",
        },
        {
            "type": "domain",
            "value": "api.example.org",
        },
    ]


def test_extract_iocs_combines_supported_types():
    text = (
        "Observed 192.0.2.22 contacting api.example.com "
        "with SHA256="
        "97AC98B1A92C286054CCE55239CFCCDFC"
        "23A5517BD07FE693072C9CA96C7DABB"
    )

    result = extract_iocs(text)

    assert result == [
        {
            "type": "sha256",
            "value": (
                "97ac98b1a92c286054cce55239cfccdfc"
                "23a5517bd07fe693072c9ca96c7dabb"
            ),
        },
        {
            "type": "ipv4",
            "value": "192.0.2.22",
        },
        {
            "type": "domain",
            "value": "api.example.com",
        },
    ]


def test_extract_domains_rejects_windows_filenames():
    text = "Observed cmd.exe rundll32.dll script.ps1 driver.sys"

    assert extract_domains(text) == []


def test_extract_domains_returns_empty_list_when_absent():
    assert extract_domains("process started successfully") == []


def test_extract_iocs_from_normalized_wazuh_alert():
    import json

    from soc_automation.normalizer import normalize_wazuh_alert

    raw = json.loads(
        Path("sample_data/wazuh/92052_raw_sanitized.json").read_text(
            encoding="utf-8-sig"
        )
    )

    alert = normalize_wazuh_alert(raw)

    result = extract_iocs_from_alert(alert)

    assert {
        "type": "sha256",
        "value": (
            "97ac98b1a92c286054cce55239cfccdfc" "23a5517bd07fe693072c9ca96c7dabb"
        ),
    } in result
