#!/usr/bin/env python3
"""Detect anomalies from correlated file policy/kernel event records.

Input records are two-element arrays:
    [normalized_user_file_policy, kernel_file_event]

The module keeps the original input intact and appends a detection result.
"""

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO


DEFAULT_PERMISSION_MAP: Mapping[str, str] = {
    "open": "read",
    "read": "read",
    "write": "write",
    "append": "write",
    "exec": "execute",
    "search": "read",
}

STATUS_INVALID_INPUT = "invalid_input"
STATUS_UNSUPPORTED_POLICY = "unsupported_policy"
STATUS_RUNTIME_ERROR = "runtime_error"
STATUS_RESOURCE_OUT_OF_SCOPE = "resource_out_of_scope"
STATUS_PERMISSION_EXCEEDED = "permission_exceeded"
STATUS_BLOCKED_VIOLATION_ATTEMPT = "blocked_violation_attempt"
STATUS_NORMAL = "normal"


def _get_path(data: Any, path: Sequence[str]) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _missing_policy_fields(policy: Any) -> List[str]:
    if not isinstance(policy, dict):
        return ["<policy_object>"]

    required = ["normalized_prefix", "actions", "effect", "resource_type"]
    return [field for field in required if field not in policy]


def _missing_event_fields(event: Any) -> List[str]:
    if not isinstance(event, dict):
        return ["<kernel_event_object>"]

    required_paths = [
        ("request", "perm"),
        ("target", "path"),
        ("result", "runtime_result"),
    ]
    return [".".join(path) for path in required_paths if _get_path(event, path) is None]


def normalize_kernel_actions(
    perm: Any,
    permission_map: Mapping[str, str] = DEFAULT_PERMISSION_MAP,
) -> List[str]:
    """Convert a kernel request.perm string into user action names."""
    if not isinstance(perm, str):
        return []

    actions: List[str] = []
    seen = set()
    for token in perm.split("|"):
        token = token.strip()
        if not token:
            continue
        action = permission_map.get(token, token)
        if action not in seen:
            actions.append(action)
            seen.add(action)
    return actions


def _status_for(
    *,
    invalid: bool,
    unsupported: bool,
    runtime_result: Optional[str],
    path_in_scope: Optional[bool],
    exceeded_actions: Sequence[str],
) -> str:
    if invalid:
        return STATUS_INVALID_INPUT
    if unsupported:
        return STATUS_UNSUPPORTED_POLICY
    if runtime_result == "error":
        return STATUS_RUNTIME_ERROR

    has_violation = path_in_scope is False or bool(exceeded_actions)
    if runtime_result == "deny" and has_violation:
        return STATUS_BLOCKED_VIOLATION_ATTEMPT
    if path_in_scope is False:
        return STATUS_RESOURCE_OUT_OF_SCOPE
    if exceeded_actions:
        return STATUS_PERMISSION_EXCEEDED
    return STATUS_NORMAL


def detect_record(
    record: Any,
    permission_map: Mapping[str, str] = DEFAULT_PERMISSION_MAP,
) -> Dict[str, Any]:
    """Detect one correlated file event record.

    The returned object contains the original input under ``input`` and a
    detector-owned ``detection`` object.
    """
    reasons: List[str] = []
    invalid = not isinstance(record, list) or len(record) != 2

    policy: Any = record[0] if isinstance(record, list) and len(record) > 0 else None
    event: Any = record[1] if isinstance(record, list) and len(record) > 1 else None

    missing_policy = _missing_policy_fields(policy)
    missing_event = _missing_event_fields(event)

    if invalid:
        reasons.append("input must be a two-element array")
    if missing_policy:
        invalid = True
        reasons.append("missing policy fields: " + ", ".join(missing_policy))
    if missing_event:
        invalid = True
        reasons.append("missing kernel event fields: " + ", ".join(missing_event))

    unsupported = False
    normalized_prefix = policy.get("normalized_prefix") if isinstance(policy, dict) else None
    actions = policy.get("actions") if isinstance(policy, dict) else None
    effect = policy.get("effect") if isinstance(policy, dict) else None
    resource_type = policy.get("resource_type") if isinstance(policy, dict) else None

    if not invalid:
        unsupported = resource_type != "file" or effect != "allow"
        if unsupported:
            reasons.append("only file allow policies are supported")

    target_path = _get_path(event, ("target", "path"))
    request_perm = _get_path(event, ("request", "perm"))
    runtime_result = _get_path(event, ("result", "runtime_result"))

    path_in_scope: Optional[bool] = None
    if not invalid and isinstance(target_path, str) and isinstance(normalized_prefix, str):
        path_in_scope = target_path.startswith(normalized_prefix)
        if not path_in_scope:
            reasons.append("target.path not under normalized_prefix")

    kernel_actions = normalize_kernel_actions(request_perm, permission_map)
    allowed_actions = actions if isinstance(actions, list) else []
    allowed_set = {action for action in allowed_actions if isinstance(action, str)}
    exceeded_actions = [action for action in kernel_actions if action not in allowed_set]

    if not invalid and exceeded_actions:
        for action in exceeded_actions:
            reasons.append(f"{action} not in actions")

    if runtime_result == "error":
        reasons.append("runtime_result is error")

    status = _status_for(
        invalid=invalid,
        unsupported=unsupported,
        runtime_result=runtime_result if isinstance(runtime_result, str) else None,
        path_in_scope=path_in_scope,
        exceeded_actions=exceeded_actions,
    )

    return {
        "input": record,
        "detection": {
            "status": status,
            "reasons": reasons,
            "kernel_actions": kernel_actions,
            "allowed_actions": allowed_actions,
            "path_in_scope": path_in_scope,
        },
    }


def detect_stream(
    lines: Iterable[str],
    permission_map: Mapping[str, str] = DEFAULT_PERMISSION_MAP,
) -> Iterable[Dict[str, Any]]:
    """Yield detection results for NDJSON correlated records."""
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            yield {
                "input": line,
                "detection": {
                    "status": STATUS_INVALID_INPUT,
                    "reasons": [f"line {lineno}: invalid json: {exc.msg}"],
                    "kernel_actions": [],
                    "allowed_actions": [],
                    "path_in_scope": None,
                },
            }
            continue
        yield detect_record(record, permission_map)


def _run(input_file: TextIO, output_file: TextIO) -> int:
    for result in detect_stream(input_file):
        output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        output_file.write("\n")
    return 0


def write_detection_log(records: Iterable[Any], output_path: str) -> None:
    """Write detection results for correlated records to an NDJSON log file."""
    with open(output_path, "w", encoding="utf-8") as output_file:
        for record in records:
            result = detect_record(record)
            output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
            output_file.write("\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect file anomalies from correlated NDJSON records.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input NDJSON file. Defaults to stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output NDJSON file. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    if args.input:
        with open(args.input, "r", encoding="utf-8") as input_file:
            if args.output:
                with open(args.output, "w", encoding="utf-8") as output_file:
                    return _run(input_file, output_file)
            return _run(input_file, sys.stdout)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            return _run(sys.stdin, output_file)
    return _run(sys.stdin, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
