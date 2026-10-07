import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.vt_normalizer import normalize_vt_success  # noqa: E402


def test_normalize_vt_success():
    payload = {
        "data": {
            "type": "domain",
            "id": "example.com",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 12,
                    "timeout": 0,
                }
            },
        }
    }

    result = normalize_vt_success("domain", "example.com", payload)

    assert result == {
        "provider": "virustotal",
        "status": "success",
        "ioc": {
            "type": "domain",
            "value": "example.com",
        },
        "stats": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 70,
            "undetected": 12,
            "timeout": 0,
        },
    }


def test_normalize_vt_success_defaults_missing_stats_to_zero():
    payload = {
        "data": {
            "type": "file",
            "id": "a" * 64,
            "attributes": {},
        }
    }

    result = normalize_vt_success("sha256", "a" * 64, payload)

    assert result["stats"] == {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
    }
