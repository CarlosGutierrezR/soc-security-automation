import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.case_builder import build_case  # noqa: E402


def test_build_case_contains_required_sections():
    case = build_case(
        alerts=[{"detection": {"rule_id": 92052}}],
        correlation={"related": True},
        iocs=[{"type": "sha256", "value": "a" * 64}],
        enrichments=[{"status": "pending_external"}],
        risk={"score": 45, "reasons": []},
        decision={
            "risk": "medium",
            "action": "analyst_review",
            "approval_required": True,
        },
    )

    assert case["alerts"][0]["detection"]["rule_id"] == 92052
    assert case["correlation"]["related"] is True
    assert case["risk"]["score"] == 45
    assert case["decision"]["action"] == "analyst_review"
    assert case["approval_required"] is True


def test_build_case_includes_audit_trail():
    case = build_case(
        alerts=[],
        correlation={"related": False},
        iocs=[],
        enrichments=[],
        risk={"score": 5, "reasons": []},
        decision={
            "risk": "low",
            "action": "summary_close_candidate",
            "approval_required": True,
        },
    )

    assert case["audit"] == [
        "alerts_normalized",
        "correlation_evaluated",
        "iocs_extracted",
        "enrichment_evaluated",
        "risk_scored",
        "decision_generated",
    ]
