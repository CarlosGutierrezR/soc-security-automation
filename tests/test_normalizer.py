import json
import sys
from pathlib import Path

sys.path.insert(0, "src")

from soc_automation.normalizer import normalize_wazuh_alert  # noqa: E402


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def test_normalize_92052():
    raw = load_json("sample_data/wazuh/92052_raw_sanitized.json")
    expected = load_json("tests/expected/92052_normalized.json")

    result = normalize_wazuh_alert(raw)

    assert result == expected


def test_normalize_92032():
    raw = load_json("sample_data/wazuh/92032_raw_sanitized.json")
    expected = load_json("tests/expected/92032_normalized.json")

    result = normalize_wazuh_alert(raw)

    assert result == expected
