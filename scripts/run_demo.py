"""Run the SEC-AUTO-001 workflow on the sanitized sample alerts.

Usage (from the repository root):
    python scripts/run_demo.py
    python scripts/run_demo.py --vt-malicious 6 --vt-suspicious 1

No network requests are made. VirusTotal statistics, when given,
are treated as already-normalized external context.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_automation.workflow import run_workflow  # noqa: E402

PARENT_SAMPLE = ROOT / "sample_data" / "wazuh" / "92052_raw_sanitized.json"
CHILD_SAMPLE = ROOT / "sample_data" / "wazuh" / "92032_raw_sanitized.json"


def non_negative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vt-malicious", type=non_negative_int, default=None)
    parser.add_argument("--vt-suspicious", type=non_negative_int, default=None)
    parser.add_argument(
        "--full",
        action="store_true",
        help="print the full case, including normalized alerts",
    )
    args = parser.parse_args()

    vt_stats = None
    if args.vt_malicious is not None or args.vt_suspicious is not None:
        vt_stats = {
            "malicious": args.vt_malicious or 0,
            "suspicious": args.vt_suspicious or 0,
        }

    case = run_workflow(
        load_json(PARENT_SAMPLE),
        load_json(CHILD_SAMPLE),
        vt_stats=vt_stats,
    )

    if not args.full:
        case = {key: value for key, value in case.items() if key != "alerts"}

    print(json.dumps(case, indent=2))


if __name__ == "__main__":
    main()
