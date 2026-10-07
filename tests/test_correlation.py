import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_automation.correlation import is_parent_child_related  # noqa: E402
from soc_automation.normalizer import normalize_wazuh_alert  # noqa: E402


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_normalized_pair():
    parent_raw = load_json("sample_data/wazuh/92052_raw_sanitized.json")
    child_raw = load_json("sample_data/wazuh/92032_raw_sanitized.json")

    return (
        normalize_wazuh_alert(parent_raw),
        normalize_wazuh_alert(child_raw),
    )


def test_parent_child_correlation_positive():
    parent, child = load_normalized_pair()

    assert is_parent_child_related(parent, child) is True


def test_parent_child_correlation_rejects_different_host():
    parent, child = load_normalized_pair()

    child = copy.deepcopy(child)
    child["agent"]["name"] = "OTHER-HOST"

    assert is_parent_child_related(parent, child) is False


def test_parent_child_correlation_rejects_wrong_guid():
    parent, child = load_normalized_pair()

    child = copy.deepcopy(child)
    child["parent_process"]["guid"] = "{99999999-9999-9999-9999-999999999999}"

    assert is_parent_child_related(parent, child) is False


def test_parent_child_correlation_rejects_outside_time_window():
    parent, child = load_normalized_pair()

    child = copy.deepcopy(child)
    child["timestamp"] = "2026-10-06T16:22:08.138Z"

    assert is_parent_child_related(parent, child, max_seconds=5) is False


def test_parent_child_correlation_rejects_wrong_pid():
    parent, child = load_normalized_pair()

    child = copy.deepcopy(child)
    child["parent_process"]["pid"] = 9999

    assert is_parent_child_related(parent, child) is False


def test_parent_child_correlation_rejects_child_before_parent():
    parent, child = load_normalized_pair()

    child = copy.deepcopy(child)
    child["timestamp"] = "2026-10-06T16:21:07.000Z"

    assert is_parent_child_related(parent, child, max_seconds=5) is False
