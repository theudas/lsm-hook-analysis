#!/usr/bin/env python3
"""Classify policy-misconfiguration anomalies into SELinux policy categories.

This is the second-stage classifier that runs after
``file_anomaly_detector``.  The first stage answers *whether* SELinux let
through an access that the user-space policy forbids.  This stage answers
*which SELinux mechanism* let it through, mapping each anomaly onto the three
categories proposed by SPRT (SACMAT 2024):

    TMM  (Type Missing/Mis-set)            -> file-label mapping  r_f
    TTLP (Transition Leads to Lax Privs)   -> type transition     r_t
    PCI  (Policy Configured Improperly)    -> allow rule          r_e

The classifier consumes the output object of ``file_anomaly_detector``
(``{"input": [policy, event], "detection": {...}}``) and appends a
``selinux_classification`` object.  An optional reference knowledge base
(three tables derived from the host policy) turns the classification from a
heuristic guess into a deterministic attribution.
"""

import argparse
import json
import re
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO


# --- Categories ----------------------------------------------------------

CATEGORY_TMM = "TMM"
CATEGORY_TTLP = "TTLP"
CATEGORY_PCI = "PCI"
CATEGORY_POLICY_CORRECT = "policy_correct"
CATEGORY_NOT_APPLICABLE = "not_applicable"

CONFIDENCE_HIGH = "high"
CONFIDENCE_LOW = "low"

# Detector statuses this stage attributes to an SELinux mechanism.  These are
# the cases where SELinux allowed an access the user-space policy forbids.
CLASSIFIABLE_STATUSES = frozenset(
    {"permission_exceeded", "resource_out_of_scope"}
)

# Detector status where SELinux already denied the violation; the policy did
# its job and there is nothing to adjust.
DENIED_STATUS = "blocked_violation_attempt"


# --- Heuristic fallbacks (used only when the reference KB is absent) ------

# Object types that are generic/shared rather than app-specific.  A
# violation against one of these without a matching reference type hints at a
# mislabel (TMM).
GENERIC_OBJECT_TYPES = frozenset(
    {
        "default_t",
        "user_home_t",
        "user_tmp_t",
        "tmp_t",
        "var_t",
        "var_lib_t",
        "etc_t",
        "unlabeled_t",
        "file_t",
    }
)

# Subject domains that carry broad privileges.  A confined operation running
# in one of these without a matching reference domain hints at a missing type
# transition (TTLP).
BROAD_SUBJECT_DOMAINS = frozenset(
    {
        "unconfined_t",
        "unconfined_service_t",
        "init_t",
        "initrc_t",
        "kernel_t",
        "sysadm_t",
        "spc_t",
    }
)


def context_type(context: Any) -> Optional[str]:
    """Return the SELinux *type* (3rd field) of a context string.

    ``user_u:role_r:httpd_t:s0-s0:c0.c1023`` -> ``httpd_t``.
    Returns ``None`` when the context is missing or malformed.
    """
    if not isinstance(context, str):
        return None
    parts = context.split(":")
    if len(parts) < 3:
        return None
    type_field = parts[2].strip()
    return type_field or None


def _get_path(data: Any, path: Sequence[str]) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


# --- Reference knowledge base -------------------------------------------
#
# A reference is a plain dict with three optional tables.  See
# docs/selinux_policy_classification_design.md for how to export each table
# from a CentOS Stream 9 host.
#
#   {
#     "file_contexts":    [{"pattern": "<regex>", "type": "<type_t>"}, ...],
#     "expected_domains": {"<comm>": "<domain_t>", ...},
#     "allow_rules":      [{"source","target","class","perms":[...]}, ...]
#   }


def lookup_expected_object_type(
    path: Any, reference: Optional[Mapping[str, Any]]
) -> Optional[str]:
    """Resolve the expected object type for ``path`` from ``file_contexts``.

    Patterns are SELinux file-context regexes matched against the full path.
    Among all matching patterns the longest pattern string wins, as a v1
    proxy for SELinux specificity ordering.
    """
    if not isinstance(path, str) or not reference:
        return None
    entries = reference.get("file_contexts")
    if not isinstance(entries, list):
        return None

    best_type: Optional[str] = None
    best_len = -1
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern")
        expected = entry.get("type")
        if not isinstance(pattern, str) or not isinstance(expected, str):
            continue
        try:
            if re.fullmatch(pattern, path) is None:
                continue
        except re.error:
            continue
        if len(pattern) > best_len:
            best_len = len(pattern)
            best_type = expected
    return best_type


def lookup_expected_domain(
    comm: Any, reference: Optional[Mapping[str, Any]]
) -> Optional[str]:
    """Resolve the expected subject domain for ``comm`` from the KB."""
    if not isinstance(comm, str) or not reference:
        return None
    domains = reference.get("expected_domains")
    if not isinstance(domains, dict):
        return None
    expected = domains.get(comm)
    return expected if isinstance(expected, str) else None


def find_allow_rule(
    source: Optional[str],
    target: Optional[str],
    tclass: Optional[str],
    perms: Sequence[str],
    reference: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Find an allow rule granting any of ``perms`` on (source, target, class)."""
    if not reference:
        return None
    rules = reference.get("allow_rules")
    if not isinstance(rules, list):
        return None

    wanted = set(perms)
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("source") != source:
            continue
        if rule.get("target") != target:
            continue
        if rule.get("class") != tclass:
            continue
        rule_perms = rule.get("perms")
        if not isinstance(rule_perms, list):
            continue
        if wanted & set(rule_perms):
            return rule
    return None


def load_reference(path: str) -> Dict[str, Any]:
    """Load a reference knowledge base from a JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("reference file must contain a JSON object")
    return data


# --- Fix recommendations -------------------------------------------------


def _fix_relabel(path: Optional[str], expected_type: str, pattern: Optional[str]) -> Dict[str, Any]:
    spec = pattern if pattern else (path or "<path>")
    restore = path if path else "<path>"
    return {
        "kind": "relabel",
        "target_type": expected_type,
        "command": (
            f"semanage fcontext -a -t {expected_type} '{spec}' && "
            f"restorecon -v {restore}"
        ),
    }


def _fix_type_transition(expected_domain: Optional[str], comm: Optional[str]) -> Dict[str, Any]:
    new_domain = expected_domain or "<confined_domain_t>"
    return {
        "kind": "type_transition",
        "expected_domain": expected_domain,
        "command": (
            f"# process '{comm or '<comm>'}' did not transition to {new_domain}; "
            f"add: type_transition <parent_t> <exec_t>:process {new_domain}; "
            "then rebuild and reload the policy module"
        ),
    }


def _fix_remove_allow(
    source: Optional[str],
    target: Optional[str],
    tclass: Optional[str],
    perms: Sequence[str],
) -> Dict[str, Any]:
    perm_str = " ".join(perms) if perms else "<perm>"
    return {
        "kind": "remove_allow",
        "command": (
            f"# locate: sesearch --allow -s {source or '<S>'} -t {target or '<T>'} "
            f"-c {tclass or '<C>'}; "
            f"then remove {{ {perm_str} }} from that allow rule and rebuild the policy"
        ),
    }


# --- Classification ------------------------------------------------------


def _result(
    category: str,
    *,
    direction: str = "allow",
    confidence: Optional[str] = None,
    observed: Optional[Dict[str, Any]] = None,
    expected: Optional[Dict[str, Any]] = None,
    evidence: Optional[List[str]] = None,
    recommended_fix: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    classification: Dict[str, Any] = {"category": category, "direction": direction}
    if confidence is not None:
        classification["confidence"] = confidence
    if observed is not None:
        classification["observed"] = observed
    if expected is not None:
        classification["expected"] = expected
    classification["evidence"] = evidence or []
    if recommended_fix is not None:
        classification["recommended_fix"] = recommended_fix
    return classification


def classify_detection(
    detection_result: Any,
    reference: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify one ``file_anomaly_detector`` output object.

    Returns the input object with an added ``selinux_classification`` field.
    Records that do not represent an allowed user-space-policy violation are
    marked ``policy_correct`` (SELinux denied it) or ``not_applicable``.
    """
    if not isinstance(detection_result, dict):
        return {
            "input": detection_result,
            "selinux_classification": _result(
                CATEGORY_NOT_APPLICABLE,
                evidence=["input is not a detection result object"],
            ),
        }

    detection = detection_result.get("detection")
    status = detection.get("status") if isinstance(detection, dict) else None

    if status == DENIED_STATUS:
        detection_result["selinux_classification"] = _result(
            CATEGORY_POLICY_CORRECT,
            evidence=["SELinux denied the violation at runtime; policy enforced correctly"],
        )
        return detection_result

    if status not in CLASSIFIABLE_STATUSES:
        detection_result["selinux_classification"] = _result(
            CATEGORY_NOT_APPLICABLE,
            evidence=[f"detector status '{status}' is not an allowed-violation case"],
        )
        return detection_result

    # Pull the kernel event (input[1]) and the labels it carries.
    record = detection_result.get("input")
    event = record[1] if isinstance(record, list) and len(record) > 1 else None

    scontext = _get_path(event, ("subject", "scontext"))
    tcontext = _get_path(event, ("target", "tcontext"))
    comm = _get_path(event, ("subject", "comm"))
    tclass = _get_path(event, ("target", "tclass"))
    path = _get_path(event, ("target", "path"))

    s_type = context_type(scontext)
    t_type = context_type(tcontext)

    kernel_actions = detection.get("kernel_actions") or []
    allowed_actions = detection.get("allowed_actions") or []
    offending = [a for a in kernel_actions if a not in set(allowed_actions)]
    # resource_out_of_scope has no per-perm overflow; the whole access is illegal.
    offending_perms = offending or list(kernel_actions)

    observed = {
        "S": s_type,
        "T": t_type,
        "C": tclass,
        "P": offending_perms,
        "path": path,
        "comm": comm,
    }

    have_reference = bool(reference)

    # Step 1: TMM -- the object label deviates from its expected type.
    expected_t = lookup_expected_object_type(path, reference)
    if expected_t is not None and t_type is not None and t_type != expected_t:
        detection_result["selinux_classification"] = _result(
            CATEGORY_TMM,
            confidence=CONFIDENCE_HIGH,
            observed=observed,
            expected={"T": expected_t},
            evidence=[
                f"object type '{t_type}' != expected '{expected_t}' for path {path}",
            ],
            recommended_fix=_fix_relabel(path, expected_t, _matched_pattern(path, reference)),
        )
        return detection_result

    # Step 2: TTLP -- the subject domain deviates from its expected domain.
    expected_s = lookup_expected_domain(comm, reference)
    if expected_s is not None and s_type is not None and s_type != expected_s:
        detection_result["selinux_classification"] = _result(
            CATEGORY_TTLP,
            confidence=CONFIDENCE_HIGH,
            observed=observed,
            expected={"S": expected_s},
            evidence=[
                f"subject domain '{s_type}' != expected '{expected_s}' for comm '{comm}'; "
                "process did not transition to its confined domain",
            ],
            recommended_fix=_fix_type_transition(expected_s, comm),
        )
        return detection_result

    # Step 3: PCI -- labels match (or no deviation found); an allow rule is
    # too permissive.
    if have_reference:
        rule = find_allow_rule(s_type, t_type, tclass, offending_perms, reference)
        evidence = ["object and subject labels match the reference; an allow rule grants the access"]
        if rule is not None:
            evidence.append(
                f"allow {s_type} {t_type}:{tclass} {{ {' '.join(rule.get('perms', []))} }};"
            )
        detection_result["selinux_classification"] = _result(
            CATEGORY_PCI,
            confidence=CONFIDENCE_HIGH,
            observed=observed,
            evidence=evidence,
            recommended_fix=_fix_remove_allow(s_type, t_type, tclass, offending_perms),
        )
        return detection_result

    # No reference KB: fall back to heuristics and mark low confidence.
    detection_result["selinux_classification"] = _classify_heuristic(
        observed, s_type, t_type, tclass, path, comm, offending_perms
    )
    return detection_result


def _matched_pattern(path: Any, reference: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Return the file_contexts pattern that resolved ``path`` (for the fix spec)."""
    if not isinstance(path, str) or not reference:
        return None
    entries = reference.get("file_contexts")
    if not isinstance(entries, list):
        return None
    best_pattern: Optional[str] = None
    best_len = -1
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("pattern")
        if not isinstance(pattern, str):
            continue
        try:
            if re.fullmatch(pattern, path) is None:
                continue
        except re.error:
            continue
        if len(pattern) > best_len:
            best_len = len(pattern)
            best_pattern = pattern
    return best_pattern


def _classify_heuristic(
    observed: Dict[str, Any],
    s_type: Optional[str],
    t_type: Optional[str],
    tclass: Optional[str],
    path: Optional[str],
    comm: Optional[str],
    offending_perms: Sequence[str],
) -> Dict[str, Any]:
    """Best-effort classification with no reference KB; always low confidence."""
    if t_type in GENERIC_OBJECT_TYPES:
        return _result(
            CATEGORY_TMM,
            confidence=CONFIDENCE_LOW,
            observed=observed,
            evidence=[
                f"no reference KB; object type '{t_type}' is generic/shared, "
                "suggesting a mislabel",
            ],
            recommended_fix=_fix_relabel(path, "<expected_type_t>", None),
        )

    if s_type in BROAD_SUBJECT_DOMAINS:
        return _result(
            CATEGORY_TTLP,
            confidence=CONFIDENCE_LOW,
            observed=observed,
            evidence=[
                f"no reference KB; subject domain '{s_type}' is broad, "
                "suggesting a missing type transition",
            ],
            recommended_fix=_fix_type_transition(None, comm),
        )

    return _result(
        CATEGORY_PCI,
        confidence=CONFIDENCE_LOW,
        observed=observed,
        evidence=[
            "no reference KB; labels look specific, suggesting an over-permissive allow rule",
        ],
        recommended_fix=_fix_remove_allow(s_type, t_type, tclass, offending_perms),
    )


def classify_stream(
    lines: Iterable[str],
    reference: Optional[Mapping[str, Any]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield classifications for NDJSON detector-output records."""
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            detection_result = json.loads(line)
        except json.JSONDecodeError as exc:
            yield {
                "input": line,
                "selinux_classification": _result(
                    CATEGORY_NOT_APPLICABLE,
                    evidence=[f"line {lineno}: invalid json: {exc.msg}"],
                ),
            }
            continue
        yield classify_detection(detection_result, reference)


def write_classification_log(
    detection_results: Iterable[Any],
    output_path: str,
    reference: Optional[Mapping[str, Any]] = None,
) -> None:
    """Classify detector outputs and write results to an NDJSON log file."""
    with open(output_path, "w", encoding="utf-8") as output_file:
        for detection_result in detection_results:
            result = classify_detection(detection_result, reference)
            output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
            output_file.write("\n")


def _run(input_file: TextIO, output_file: TextIO, reference: Optional[Mapping[str, Any]]) -> int:
    for result in classify_stream(input_file, reference):
        output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        output_file.write("\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify file-anomaly detections into SELinux policy categories.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input NDJSON file of file_anomaly_detector outputs. Defaults to stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output NDJSON file. Defaults to stdout.",
    )
    parser.add_argument(
        "-r",
        "--reference",
        help="Optional reference knowledge base (JSON). Without it, classification is heuristic.",
    )
    args = parser.parse_args(argv)

    reference = load_reference(args.reference) if args.reference else None

    if args.input:
        with open(args.input, "r", encoding="utf-8") as input_file:
            if args.output:
                with open(args.output, "w", encoding="utf-8") as output_file:
                    return _run(input_file, output_file, reference)
            return _run(input_file, sys.stdout, reference)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            return _run(sys.stdin, output_file, reference)
    return _run(sys.stdin, sys.stdout, reference)


if __name__ == "__main__":
    raise SystemExit(main())
