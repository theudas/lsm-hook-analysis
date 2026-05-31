#!/usr/bin/env python3
"""Attribute SELinux AVC *deny* events to a policy mechanism.

This is the deny-direction counterpart to ``selinux_policy_classifier``.
Where the allow-direction asks *which mechanism let through an access the
user forbade*, this module asks *which mechanism blocked an access the user
intended to allow* -- i.e. an availability problem rather than a privilege
escalation.

Input is a correlated record ``[user_file_policy, avc_event]`` where
``avc_event`` is the user-space form of ``struct lha_avc_event_v1`` (flat
fields: ``scontext``/``tcontext``/``tclass``/``perm``/``comm``/``permissive``/
``denied``).  Note the AVC event carries **no path** -- the intended resource
(and therefore its expected label) comes from the correlated user-space
policy.

The three root-cause mechanisms mirror SPRT, but the fix direction is the
opposite of the allow-direction:

    TMM           object mislabeled -> a legitimate access is denied     (relabel)
    TTLP          subject in wrong domain, lacks privilege               (add/fix transition)
    missing_allow labels correct but no allow rule grants the perm       (add allow rule)

A deny whose access falls *outside* the user-intended actions is correct
enforcement and is reported as ``policy_correct``.
"""

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO

from .file_anomaly_detector import normalize_kernel_actions
from .selinux_policy_classifier import (
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_POLICY_CORRECT,
    CATEGORY_TMM,
    CATEGORY_TTLP,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    GENERIC_OBJECT_TYPES,
    _fix_relabel,
    _fix_type_transition,
    _matched_pattern,
    _result,
    context_type,
    find_allow_rule,
    lookup_expected_domain,
    lookup_expected_object_type,
)

DIRECTION = "deny"

# Deny-direction category for "labels are right but no allow rule grants it".
CATEGORY_MISSING_ALLOW = "missing_allow"
# A rule does grant the perm yet the access was still denied -- root cause is
# outside the three mechanisms (booleans, MLS/constraints, neverallow, bounds).
CATEGORY_UNDETERMINED = "undetermined"

# Fields the flat AVC event must carry to be classifiable.
_REQUIRED_AVC_FIELDS = ("scontext", "tcontext", "tclass", "perm")


def _deny_result(category: str, **kwargs: Any) -> Dict[str, Any]:
    return _result(category, direction=DIRECTION, **kwargs)


def _representative_path(policy: Any) -> Optional[str]:
    """Derive a concrete-ish path from a policy for file_contexts lookup.

    The AVC event has no path, so the intended resource is approximated from
    the policy's ``normalized_prefix`` (preferred) or ``identifier`` with its
    glob tail stripped.
    """
    if not isinstance(policy, dict):
        return None
    prefix = policy.get("normalized_prefix")
    if isinstance(prefix, str) and prefix:
        return prefix.rstrip("/") or "/"
    identifier = policy.get("identifier")
    if isinstance(identifier, str) and identifier:
        head = identifier.split("*", 1)[0]
        return head.rstrip("/") or "/"
    return None


def _fix_add_allow(
    source: Optional[str],
    target: Optional[str],
    tclass: Optional[str],
    perms: Sequence[str],
) -> Dict[str, Any]:
    perm_str = " ".join(perms) if perms else "<perm>"
    return {
        "kind": "add_allow",
        "command": (
            f"# add: allow {source or '<S>'} {target or '<T>'}:{tclass or '<C>'} "
            f"{{ {perm_str} }}; then rebuild and reload the policy module "
            f"(e.g. via audit2allow on the matching AVC)"
        ),
    }


def classify_avc_deny(
    record: Any,
    reference: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify one correlated ``[policy, avc_event]`` deny record."""
    if not isinstance(record, list) or len(record) != 2:
        return {
            "input": record,
            "selinux_classification": _deny_result(
                CATEGORY_NOT_APPLICABLE,
                evidence=["input must be a [policy, avc_event] two-element array"],
            ),
        }

    policy, avc = record[0], record[1]

    if not isinstance(avc, dict) or any(
        not isinstance(avc.get(field), str) or not avc.get(field)
        for field in _REQUIRED_AVC_FIELDS
    ):
        return {
            "input": record,
            "selinux_classification": _deny_result(
                CATEGORY_NOT_APPLICABLE,
                evidence=[
                    "avc_event missing required fields: "
                    + ", ".join(_REQUIRED_AVC_FIELDS)
                ],
            ),
        }

    if not avc.get("denied"):
        return {
            "input": record,
            "selinux_classification": _deny_result(
                CATEGORY_NOT_APPLICABLE,
                evidence=["avc_event.denied is not set; not a deny event"],
            ),
        }

    s_type = context_type(avc.get("scontext"))
    t_type = context_type(avc.get("tcontext"))
    tclass = avc.get("tclass")
    comm = avc.get("comm")
    permissive = bool(avc.get("permissive"))
    kernel_actions = normalize_kernel_actions(avc.get("perm"))

    # Intent check: only a deny that the user *meant* to allow is an anomaly.
    usable_policy = (
        isinstance(policy, dict)
        and policy.get("effect") == "allow"
        and policy.get("resource_type") == "file"
        and isinstance(policy.get("actions"), list)
    )
    if not usable_policy:
        return {
            "input": record,
            "selinux_classification": _deny_result(
                CATEGORY_NOT_APPLICABLE,
                evidence=[
                    "no correlated file allow policy; cannot determine whether the "
                    "deny blocked an intended access"
                ],
            ),
        }

    allowed_actions = [a for a in policy["actions"] if isinstance(a, str)]
    intended = [a for a in kernel_actions if a in set(allowed_actions)]
    if not intended:
        record_out = {"input": record}
        record_out["selinux_classification"] = _deny_result(
            CATEGORY_POLICY_CORRECT,
            evidence=[
                "denied actions "
                f"{kernel_actions} are outside user-intended actions "
                f"{allowed_actions}; SELinux enforcement is correct"
            ],
        )
        return record_out

    observed = {
        "S": s_type,
        "T": t_type,
        "C": tclass,
        "P": intended,
        "comm": comm,
        "permissive": permissive,
    }
    permissive_note = (
        [
            "permissive mode: the deny was audited but not enforced; this predicts "
            "an enforcing-mode failure"
        ]
        if permissive
        else []
    )

    record_out: Dict[str, Any] = {"input": record}
    resource_path = _representative_path(policy)

    # Step 1: TMM -- the object is mislabeled, so a legitimate access is denied.
    expected_t = lookup_expected_object_type(resource_path, reference)
    if expected_t is not None and t_type is not None and t_type != expected_t:
        record_out["selinux_classification"] = _deny_result(
            CATEGORY_TMM,
            confidence=CONFIDENCE_HIGH,
            observed=observed,
            expected={"T": expected_t},
            evidence=[
                f"object type '{t_type}' != expected '{expected_t}' for resource "
                f"{resource_path}; the mislabel blocks the intended access",
            ]
            + permissive_note,
            recommended_fix=_fix_relabel(
                resource_path, expected_t, _matched_pattern(resource_path, reference)
            ),
        )
        return record_out

    # Step 2: TTLP -- the subject is in the wrong domain and lacks privilege.
    expected_s = lookup_expected_domain(comm, reference)
    if expected_s is not None and s_type is not None and s_type != expected_s:
        record_out["selinux_classification"] = _deny_result(
            CATEGORY_TTLP,
            confidence=CONFIDENCE_HIGH,
            observed=observed,
            expected={"S": expected_s},
            evidence=[
                f"subject domain '{s_type}' != expected '{expected_s}' for comm "
                f"'{comm}'; the process lacks the privileges of its proper domain",
            ]
            + permissive_note,
            recommended_fix=_fix_type_transition(expected_s, comm),
        )
        return record_out

    # Step 3: labels look correct.  Either an allow rule is missing, or a rule
    # exists and the deny is caused by something outside the three mechanisms.
    if reference:
        rule = find_allow_rule(s_type, t_type, tclass, intended, reference)
        if rule is None:
            record_out["selinux_classification"] = _deny_result(
                CATEGORY_MISSING_ALLOW,
                confidence=CONFIDENCE_HIGH,
                observed=observed,
                evidence=[
                    "object and subject labels match the reference, but no allow "
                    f"rule grants {intended} on {s_type} {t_type}:{tclass}",
                ]
                + permissive_note,
                recommended_fix=_fix_add_allow(s_type, t_type, tclass, intended),
            )
            return record_out

        record_out["selinux_classification"] = _deny_result(
            CATEGORY_UNDETERMINED,
            confidence=CONFIDENCE_LOW,
            observed=observed,
            evidence=[
                f"an allow rule grants {rule.get('perms')} on {s_type} "
                f"{t_type}:{tclass} yet the access was denied; check booleans, "
                "MLS/constraints, neverallow, or type bounds",
            ]
            + permissive_note,
        )
        return record_out

    # No reference KB: best-effort heuristic, always low confidence.
    record_out["selinux_classification"] = _classify_deny_heuristic(
        observed, s_type, t_type, tclass, resource_path, intended, permissive_note
    )
    return record_out


def _classify_deny_heuristic(
    observed: Dict[str, Any],
    s_type: Optional[str],
    t_type: Optional[str],
    tclass: Optional[str],
    resource_path: Optional[str],
    intended: Sequence[str],
    permissive_note: List[str],
) -> Dict[str, Any]:
    """Deny-direction heuristic with no reference KB.

    A confined process being denied on a generic/shared object label most
    often means the object is mislabeled (TMM); otherwise the likeliest cause
    is a missing allow rule.  We deliberately do not guess TTLP here -- a
    broad subject domain is rarely the one being denied, and without the KB we
    cannot tell which domain a process *should* run in.
    """
    if t_type in GENERIC_OBJECT_TYPES:
        return _deny_result(
            CATEGORY_TMM,
            confidence=CONFIDENCE_LOW,
            observed=observed,
            evidence=[
                f"no reference KB; object type '{t_type}' is generic/shared, "
                "suggesting the resource is mislabeled and should be relabeled",
            ]
            + permissive_note,
            recommended_fix=_fix_relabel(resource_path, "<expected_type_t>", None),
        )

    return _deny_result(
        CATEGORY_MISSING_ALLOW,
        confidence=CONFIDENCE_LOW,
        observed=observed,
        evidence=[
            "no reference KB; labels look specific, suggesting an allow rule is "
            "missing for the intended access",
        ]
        + permissive_note,
        recommended_fix=_fix_add_allow(s_type, t_type, tclass, intended),
    )


def classify_avc_stream(
    lines: Iterable[str],
    reference: Optional[Mapping[str, Any]] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield classifications for NDJSON ``[policy, avc_event]`` records."""
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            yield {
                "input": line,
                "selinux_classification": _deny_result(
                    CATEGORY_NOT_APPLICABLE,
                    evidence=[f"line {lineno}: invalid json: {exc.msg}"],
                ),
            }
            continue
        yield classify_avc_deny(record, reference)


def write_avc_classification_log(
    records: Iterable[Any],
    output_path: str,
    reference: Optional[Mapping[str, Any]] = None,
) -> None:
    """Classify deny records and write results to an NDJSON log file."""
    with open(output_path, "w", encoding="utf-8") as output_file:
        for record in records:
            result = classify_avc_deny(record, reference)
            output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
            output_file.write("\n")


def _run(input_file: TextIO, output_file: TextIO, reference: Optional[Mapping[str, Any]]) -> int:
    for result in classify_avc_stream(input_file, reference):
        output_file.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        output_file.write("\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attribute SELinux AVC deny events to a policy mechanism.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input NDJSON file of [policy, avc_event] records. Defaults to stdin.",
    )
    parser.add_argument("-o", "--output", help="Output NDJSON file. Defaults to stdout.")
    parser.add_argument(
        "-r",
        "--reference",
        help="Optional reference knowledge base (JSON). Without it, classification is heuristic.",
    )
    args = parser.parse_args(argv)

    # Imported lazily to avoid a hard dependency when used as a library.
    from .selinux_policy_classifier import load_reference

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
