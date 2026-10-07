import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.risk_scoring import calculate_risk_score  # noqa: E402


def test_risk_score_correlated_medium_wazuh_with_ioc():
    result = calculate_risk_score(
        wazuh_level=4,
        correlated_process_chain=True,
        ioc_count=1,
    )

    assert result["score"] == 45

    assert result["reasons"] == [
        {
            "signal": "correlated_process_chain",
            "points": 20,
        },
        {
            "signal": "wazuh_level_4_6",
            "points": 15,
        },
        {
            "signal": "ioc_present",
            "points": 10,
        },
    ]


def test_risk_score_with_virustotal_malicious_hits():
    result = calculate_risk_score(
        wazuh_level=4,
        correlated_process_chain=True,
        ioc_count=1,
        vt_stats={
            "malicious": 6,
            "suspicious": 1,
        },
    )

    assert result["score"] == 85


def test_risk_score_high_context():
    result = calculate_risk_score(
        wazuh_level=12,
        correlated_process_chain=True,
        ioc_count=3,
        vt_stats={
            "malicious": 20,
            "suspicious": 4,
        },
    )

    assert result["score"] == 95


def test_risk_score_low_wazuh_without_other_context():
    result = calculate_risk_score(
        wazuh_level=2,
    )

    assert result["score"] == 5
