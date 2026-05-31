#!/usr/bin/env python3
"""Export a SELinux reference knowledge base for the policy classifier.

This is a *host-side* helper meant to run on the CentOS Stream 9 box whose
policy is being analysed.  It shells out to ``semanage`` and ``sesearch`` and
assembles the three reference tables consumed by
``selinux_policy_classifier``:

    file_contexts     <- semanage fcontext -l         (r_f: path regex -> type)
    expected_domains  <- sesearch --type_trans + fc   (r_t, simplified: comm -> domain)
    allow_rules       <- sesearch --allow             (r_e: (S,T,class) -> perms)

The fragile text parsing lives in pure functions (``parse_fcontext_list``,
``parse_type_transitions``, ``parse_allow_rules``, ``build_expected_domains``)
so it can be unit-tested without a SELinux host.  ``main`` only handles the
subprocess plumbing.

Requires: policycoreutils-python-utils (semanage), setools-console (sesearch).
"""

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence


# Linux task comm is truncated to 15 chars (TASK_COMM_LEN - 1); the kernel
# events expose the same truncated name, so derived comms must match.
COMM_MAX_LEN = 15

# Characters that mark a file-context pattern as a regex rather than a literal
# path.  Only literal paths can be reduced to a clean basename/comm.
_REGEX_METACHARS = set(r"[](){}.*+?^$\|")

_CONTEXT_RE = re.compile(r"^[\w.-]+:[\w.-]+:[\w.-]+(?::.*)?$")


def context_type(context: str) -> Optional[str]:
    """Return the type (3rd field) of a context string, or None."""
    if not isinstance(context, str):
        return None
    parts = context.split(":")
    if len(parts) < 3:
        return None
    return parts[2].strip() or None


def _collapse_colon_spacing(line: str) -> str:
    """Normalise ``a : b`` and ``a:b`` spacing so parsing is uniform."""
    return re.sub(r"\s*:\s*", ":", line)


# --- semanage fcontext -l ------------------------------------------------


def parse_fcontext_list(text: str) -> List[Dict[str, str]]:
    """Parse ``semanage fcontext -l`` output into file_contexts entries.

    Each data row is three columns separated by 2+ spaces:
        <pattern>   <file type>   <context>
    Equivalence/header lines and ``<<none>>`` contexts are skipped.
    """
    entries: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        fields = re.split(r"\s{2,}", line.strip())
        if len(fields) != 3:
            continue
        pattern, _file_type, context = fields
        if context == "<<none>>" or not _CONTEXT_RE.match(context):
            continue
        type_name = context_type(context)
        if not type_name:
            continue
        entries.append({"pattern": pattern, "type": type_name})
    return entries


# --- sesearch --type_trans ----------------------------------------------


def parse_type_transitions(text: str) -> List[Dict[str, str]]:
    """Parse ``sesearch --type_trans`` output into transition records.

    Handles both ``src exec:process dest;`` and the spaced
    ``src exec : process dest;`` variants, plus optional named-file
    transitions (a trailing quoted name, which is ignored here).
    """
    records: List[Dict[str, str]] = []
    pattern = re.compile(
        r"^type_transition\s+(\S+)\s+(\S+):(\S+)\s+(\S+?)(?:\s+\S+)?;"
    )
    for raw in text.splitlines():
        line = _collapse_colon_spacing(raw.strip())
        match = pattern.match(line)
        if not match:
            continue
        source, target, tclass, default = match.groups()
        records.append(
            {
                "source": source,
                "target": target,
                "class": tclass,
                "default": default,
            }
        )
    return records


# --- sesearch --allow ----------------------------------------------------


def parse_allow_rules(text: str) -> List[Dict[str, Any]]:
    """Parse ``sesearch --allow`` output into allow_rule records.

    Matches ``allow SOURCE TARGET:CLASS { p1 p2 };`` and the single-perm
    ``allow SOURCE TARGET:CLASS perm;`` form.  ``allowxperm`` and other
    rule kinds are ignored.
    """
    rules: List[Dict[str, Any]] = []
    pattern = re.compile(r"^allow\s+(\S+)\s+(\S+):(\S+)\s+(.+);$")
    for raw in text.splitlines():
        line = _collapse_colon_spacing(raw.strip())
        match = pattern.match(line)
        if not match:
            continue
        source, target, tclass, perm_blob = match.groups()
        perm_blob = perm_blob.strip()
        if perm_blob.startswith("{"):
            perm_blob = perm_blob.strip("{} ")
        perms = [p for p in perm_blob.split() if p]
        if not perms:
            continue
        rules.append(
            {
                "source": source,
                "target": target,
                "class": tclass,
                "perms": perms,
            }
        )
    return rules


# --- expected_domains derivation ----------------------------------------


def _is_literal_path(pattern: str) -> bool:
    return pattern.startswith("/") and not any(c in _REGEX_METACHARS for c in pattern)


def build_expected_domains(
    type_transitions: Sequence[Mapping[str, str]],
    file_contexts: Sequence[Mapping[str, str]],
) -> Dict[str, str]:
    """Derive a ``comm -> expected domain`` map.

    For every ``process`` type transition (``src exec:process dest``), the
    executable type is mapped back to literal paths via file_contexts; the
    path basename (truncated to COMM_MAX_LEN) becomes the comm key and the
    transition's default domain becomes its value.  First mapping wins;
    conflicting comms are skipped so an ambiguous name never yields a wrong
    high-confidence answer.
    """
    exec_type_to_domain: Dict[str, str] = {}
    for record in type_transitions:
        if record.get("class") != "process":
            continue
        exec_type = record.get("target")
        domain = record.get("default")
        if exec_type and domain and exec_type not in exec_type_to_domain:
            exec_type_to_domain[exec_type] = domain

    domains: Dict[str, str] = {}
    conflicts = set()
    for entry in file_contexts:
        type_name = entry.get("type")
        pattern = entry.get("pattern")
        if type_name not in exec_type_to_domain:
            continue
        if not isinstance(pattern, str) or not _is_literal_path(pattern):
            continue
        comm = pattern.rsplit("/", 1)[-1][:COMM_MAX_LEN]
        if not comm:
            continue
        domain = exec_type_to_domain[type_name]
        if comm in domains and domains[comm] != domain:
            conflicts.add(comm)
            continue
        domains.setdefault(comm, domain)

    for comm in conflicts:
        domains.pop(comm, None)
    return domains


# --- assembly + subprocess plumbing -------------------------------------


def build_reference(
    fcontext_text: str,
    type_trans_text: str,
    allow_text: Optional[str],
) -> Dict[str, Any]:
    """Assemble the reference JSON object from raw command outputs."""
    file_contexts = parse_fcontext_list(fcontext_text)
    type_transitions = parse_type_transitions(type_trans_text)
    reference: Dict[str, Any] = {
        "file_contexts": file_contexts,
        "expected_domains": build_expected_domains(type_transitions, file_contexts),
    }
    if allow_text is not None:
        reference["allow_rules"] = parse_allow_rules(allow_text)
    return reference


def _run_command(cmd: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(cmd),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"command not found: {cmd[0]} ({exc})")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"command failed ({' '.join(cmd)}): {exc.stderr.strip() or exc}"
        )
    return completed.stdout


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export a SELinux reference knowledge base (JSON) for the policy classifier.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON file. Defaults to stdout.",
    )
    parser.add_argument(
        "--classes",
        default="file,dir,lnk_file",
        help="Comma-separated object classes to export allow rules for "
        "(default: file,dir,lnk_file). Use 'all' to export every class.",
    )
    parser.add_argument(
        "--no-allow",
        action="store_true",
        help="Skip allow-rule export (smaller output; PCI evidence will lack the exact rule).",
    )
    args = parser.parse_args(argv)

    fcontext_text = _run_command(["semanage", "fcontext", "-l"])
    type_trans_text = _run_command(["sesearch", "--type_trans"])

    allow_text: Optional[str] = None
    if not args.no_allow:
        allow_cmd = ["sesearch", "--allow"]
        if args.classes and args.classes != "all":
            for tclass in args.classes.split(","):
                tclass = tclass.strip()
                if tclass:
                    allow_cmd += ["-c", tclass]
        allow_text = _run_command(allow_cmd)

    reference = build_reference(fcontext_text, type_trans_text, allow_text)

    payload = json.dumps(reference, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")
    else:
        sys.stdout.write(payload)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
