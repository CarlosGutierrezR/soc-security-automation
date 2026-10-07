import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.decision_policy import decide_action  # noqa: E402


def test_decision_policy_low():
    assert decide_action(20) == {
        "risk": "low",
        "action": "summary_close_candidate",
        "approval_required": True,
    }


def test_decision_policy_medium():
    assert decide_action(45) == {
        "risk": "medium",
        "action": "analyst_review",
        "approval_required": True,
    }


def test_decision_policy_high():
    assert decide_action(85) == {
        "risk": "high",
        "action": "create_case_and_propose_containment",
        "approval_required": True,
    }


def test_decision_policy_boundary_30_is_medium():
    assert decide_action(30)["risk"] == "medium"


def test_decision_policy_boundary_70_is_high():
    assert decide_action(70)["risk"] == "high"


def test_decision_policy_rejects_invalid_score():
    with pytest.raises(ValueError):
        decide_action(101)
