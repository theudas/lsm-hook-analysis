#!/usr/bin/env python3
import argparse
import collections
import errno
import json
import sys
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str
    rule: str
    message: str


def load_events(path: str):
    fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"line {lineno}: invalid json: {exc}") from exc


def summarize_event(event):
    subject = event["subject"]
    request = event["request"]
    target = event["target"]
    path = event["path"]
    result = event["result"]
    return (
        f"pid={subject['tgid']}/{subject['tid']} comm={subject['comm']} "
        f"hook={request['hook']} phase={request['phase']} perm={request['perm']} "
        f"target={target['dev']}:{target['ino']}({target['type']}) "
        f"path={path['path']} ret={result['ret']}"
    )


def analyze(events):
    findings = []
    path_walk_counts = collections.Counter()
    unique_dir_search = collections.defaultdict(set)
    open_seen = set()
    duration_buckets = collections.defaultdict(list)

    for event in events:
        subject = event["subject"]
        request = event["request"]
        target = event["target"]
        path = event["path"]
        result = event["result"]
        key = (subject["tgid"], target["dev"], target["ino"])

        duration_buckets[request["hook"]].append(event["duration_ns"])

        if request["hook"] == "selinux_file_open":
            open_seen.add(key)

        if request["hook"] == "selinux_inode_permission" and request["phase"] == "path_walk":
            path_walk_counts[(subject["tgid"], subject["tid"])] += 1
            unique_dir_search[(subject["tgid"], subject["tid"])].add(
                (target["dev"], target["ino"], path["path"])
            )

        if result["runtime_result"] == "deny":
            findings.append(
                Finding(
                    "high",
                    "selinux_deny",
                    "SELinux 在运行时拒绝访问: " + summarize_event(event),
                )
            )

        elif result["ret"] == -errno.ECHILD:
            findings.append(
                Finding(
                    "medium",
                    "may_not_block_echild",
                    "命中 -ECHILD，通常表示 MAY_NOT_BLOCK/RCU 路径下无法安全重验证，"
                    "不应直接当成策略 deny: " + summarize_event(event),
                )
            )

        if request["hook"] == "selinux_file_permission" and key not in open_seen:
            findings.append(
                Finding(
                    "medium",
                    "fd_use_without_open_snapshot",
                    "观察到 file_permission 但当前输入流里没有匹配到 file_open，"
                    "可能是继承/传递 fd，也可能是采集窗口不完整: " + summarize_event(event),
                )
            )

    for task_key, count in path_walk_counts.items():
        if count >= 20:
            findings.append(
                Finding(
                    "medium",
                    "deep_path_walk",
                    f"线程 {task_key[0]}/{task_key[1]} 出现 {count} 次 path_walk inode 检查，"
                    "可能是深层路径、目录扫描或遍历型行为。",
                )
            )

    for task_key, dirs in unique_dir_search.items():
        if len(dirs) >= 12:
            findings.append(
                Finding(
                    "medium",
                    "wide_directory_scan",
                    f"线程 {task_key[0]}/{task_key[1]} 命中了 {len(dirs)} 个不同目录 inode，"
                    "更像目录扇出遍历而非单点文件访问。",
                )
            )

    for hook, samples in duration_buckets.items():
        if not samples:
            continue
        samples.sort()
        p95 = samples[int(len(samples) * 0.95) - 1 if len(samples) > 1 else 0]
        if hook == "selinux_file_permission" and p95 > 200_000:
            findings.append(
                Finding(
                    "low",
                    "slow_file_permission_tail",
                    f"{hook} 的 95 分位时延约为 {p95}ns，"
                    "说明部分请求可能走了更重的重验证路径。",
                )
            )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (severity_order[item.severity], item.rule, item.message))
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Analyze JSONL exported by the lsm_hook_analysis kernel module."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input JSONL file, or - for stdin",
    )
    args = parser.parse_args()

    events = list(load_events(args.input))
    findings = analyze(events)

    print(f"events={len(events)}")
    if not findings:
        print("findings=0")
        print("未发现高置信度异常。仍建议结合 permissive/enforcing 状态与完整审计日志复核。")
        return

    print(f"findings={len(findings)}")
    for item in findings:
        print(f"[{item.severity}] {item.rule}: {item.message}")


if __name__ == "__main__":
    main()
