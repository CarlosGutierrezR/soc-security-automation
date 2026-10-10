import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.workflow import run_workflow  # noqa: E402


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_case_inputs():
    parent_raw = load_json("sample_data/wazuh/92052_raw_sanitized.json")

    child_raw = load_json("sample_data/wazuh/92032_raw_sanitized.json")

    return parent_raw, child_raw


def test_workflow_end_to_end_dry_run():
    parent_raw, child_raw = load_case_inputs()

    case = run_workflow(
        parent_raw,
        child_raw,
    )

    assert len(case["alerts"]) == 2

    assert case["correlation"] == {
        "related": True,
        "type": "process_parent_child",
    }

    assert case["risk"]["score"] == 45
    assert case["decision"]["risk"] == "medium"
    assert case["decision"]["action"] == "analyst_review"
    assert case["approval_required"] is True

    assert len(case["iocs"]) == 2
    assert all(ioc["type"] == "sha256" for ioc in case["iocs"])


def test_workflow_external_context_can_raise_risk():
    parent_raw, child_raw = load_case_inputs()

    case = run_workflow(
        parent_raw,
        child_raw,
        vt_stats={
            "malicious": 6,
            "suspicious": 1,
        },
    )

    assert case["risk"]["score"] == 85
    assert case["decision"]["risk"] == "high"

    assert case["decision"]["action"] == ("create_case_and_propose_containment")

    assert case["approval_required"] is True
