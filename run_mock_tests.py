#!/usr/bin/env python3
from pathlib import Path
import sys

from analyze_events import analyze, load_events


BASE_DIR = Path(__file__).resolve().parent
MOCK_DIR = BASE_DIR / "mock-data"

CASES = [
    {
        "name": "normal_access",
        "file": MOCK_DIR / "normal_access.jsonl",
        "expected_rules": set(),
    },
    {
        "name": "deny_access",
        "file": MOCK_DIR / "deny_access.jsonl",
        "expected_rules": {"selinux_deny"},
    },
    {
        "name": "echild_special",
        "file": MOCK_DIR / "echild_special.jsonl",
        "expected_rules": {"may_not_block_echild"},
    },
    {
        "name": "scan_and_slow_io",
        "file": MOCK_DIR / "scan_and_slow_io.jsonl",
        "expected_rules": {
            "deep_path_walk",
            "wide_directory_scan",
            "fd_use_without_open_snapshot",
            "slow_file_permission_tail",
        },
    },
]


def main() -> int:
    failed = False

    print(f"mock_dir={MOCK_DIR}")
    for case in CASES:
        events = list(load_events(str(case["file"])))
        findings = analyze(events)
        rules = {item.rule for item in findings}
        missing = case["expected_rules"] - rules
        unexpected = rules - case["expected_rules"]

        status = "PASS"
        if missing or unexpected:
            status = "FAIL"
            failed = True

        print(
            f"[{status}] {case['name']}: events={len(events)} "
            f"expected={sorted(case['expected_rules'])} actual={sorted(rules)}"
        )
        if missing:
            print(f"  missing={sorted(missing)}")
        if unexpected:
            print(f"  unexpected={sorted(unexpected)}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
