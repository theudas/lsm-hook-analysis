import json
import os
import unittest

from detection.file_anomaly_detector import (
    STATUS_BLOCKED_VIOLATION_ATTEMPT,
    STATUS_INVALID_INPUT,
    STATUS_NORMAL,
    STATUS_PERMISSION_EXCEEDED,
    STATUS_RESOURCE_OUT_OF_SCOPE,
    STATUS_RUNTIME_ERROR,
    STATUS_UNSUPPORTED_POLICY,
    detect_record,
    detect_stream,
    normalize_kernel_actions,
    write_detection_log,
)


TEST_DIR = os.path.dirname(__file__)
TEST_LOG_PATH = os.path.join(TEST_DIR, "file_anomaly_events.test.ndjson")


def make_policy(**overrides):
    policy = {
        "policy_ref": "policies[1]",
        "subject": "file",
        "effect": "allow",
        "resource_type": "file",
        "identifier": "/workspace/outputs/**",
        "normalized_prefix": "/workspace/outputs/",
        "actions": ["read", "write", "create"],
    }
    policy.update(overrides)
    return policy


def make_event(**overrides):
    event = {
        "hook": "selinux_file_open",
        "hook_signature": "static int selinux_file_open(struct file *file)",
        "timestamp_ns": 1778482476753106527,
        "subject": {
            "pid": 14942,
            "tid": 14942,
            "scontext": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
            "comm": "tee",
        },
        "request": {
            "mask_raw": 0,
            "obj_type": "reg",
            "perm": "open|read",
        },
        "target": {
            "dev": "dm-0",
            "ino": 34803941,
            "type": "reg",
            "path": "/workspace/outputs/week_report.md",
            "tclass": "file",
            "tcontext": "system_u:object_r:user_home_t:s0",
        },
        "result": {
            "ret": 0,
            "runtime_result": "allow",
            "policy_result": "inferred_allow",
        },
    }

    for key, value in overrides.items():
        if key == "request_perm":
            event["request"]["perm"] = value
        elif key == "target_path":
            event["target"]["path"] = value
        elif key == "runtime_result":
            event["result"]["runtime_result"] = value
        else:
            event[key] = value
    return event


class FileAnomalyDetectorTest(unittest.TestCase):
    def test_normalizes_kernel_permissions(self):
        # 覆盖权限归一化规则：
        # open/read 都映射为 read，append 映射为 write，exec 映射为 execute。
        self.assertEqual(normalize_kernel_actions("open|read|append"), ["read", "write"])
        self.assertEqual(normalize_kernel_actions("exec"), ["execute"])
        self.assertEqual(normalize_kernel_actions(""), [])

    def test_normal_sample(self):
        # 覆盖正常样例：
        # target.path 在 normalized_prefix 下，open|read 归一化后为 read，
        # read 被用户态 actions 覆盖，因此检测结果应为 normal。
        result = detect_record([make_policy(), make_event()])

        self.assertEqual(result["detection"]["status"], STATUS_NORMAL)
        self.assertEqual(result["detection"]["kernel_actions"], ["read"])
        self.assertEqual(result["detection"]["allowed_actions"], ["read", "write", "create"])
        self.assertTrue(result["detection"]["path_in_scope"])
        self.assertEqual(result["detection"]["reasons"], [])

    def test_permission_exceeded(self):
        # 覆盖权限越界：
        # 内核态请求 exec，归一化为 execute，但用户态 actions 只有
        # read/write/create，因此应判定为 permission_exceeded。
        result = detect_record([make_policy(), make_event(request_perm="exec")])

        self.assertEqual(result["detection"]["status"], STATUS_PERMISSION_EXCEEDED)
        self.assertEqual(result["detection"]["kernel_actions"], ["execute"])
        self.assertIn("execute not in actions", result["detection"]["reasons"])

    def test_resource_out_of_scope(self):
        # 覆盖资源范围越界：
        # 关联输入中的 target.path 不在 normalized_prefix 下，
        # 即使权限本身可被覆盖，也应判定为 resource_out_of_scope。
        result = detect_record([make_policy(), make_event(target_path="/etc/hosts")])

        self.assertEqual(result["detection"]["status"], STATUS_RESOURCE_OUT_OF_SCOPE)
        self.assertFalse(result["detection"]["path_in_scope"])
        self.assertIn("target.path not under normalized_prefix", result["detection"]["reasons"])

    def test_blocked_violation_attempt(self):
        # 覆盖被内核拒绝的异常尝试：
        # exec 超出用户态 actions，但 runtime_result 为 deny，说明内核已经拒绝，
        # 因此输出 blocked_violation_attempt，而不是普通 permission_exceeded。
        result = detect_record([
            make_policy(),
            make_event(request_perm="exec", runtime_result="deny"),
        ])

        self.assertEqual(result["detection"]["status"], STATUS_BLOCKED_VIOLATION_ATTEMPT)
        self.assertIn("execute not in actions", result["detection"]["reasons"])

    def test_runtime_error_has_priority(self):
        # 覆盖运行时错误优先级：
        # 即使请求权限也存在越界，只要 runtime_result 为 error，
        # 当前 v1 优先输出 runtime_error，避免把错误态误判为已执行越权。
        result = detect_record([
            make_policy(),
            make_event(request_perm="exec", runtime_result="error"),
        ])

        self.assertEqual(result["detection"]["status"], STATUS_RUNTIME_ERROR)
        self.assertIn("runtime_result is error", result["detection"]["reasons"])

    def test_invalid_input(self):
        # 覆盖输入结构错误：
        # 检测模块要求输入必须是 [policy, kernel_event] 二元数组。
        result = detect_record({"not": "a correlated record"})

        self.assertEqual(result["detection"]["status"], STATUS_INVALID_INPUT)
        self.assertIn("input must be a two-element array", result["detection"]["reasons"])

    def test_missing_fields(self):
        # 覆盖必要字段缺失：
        # kernel event 缺少 request.perm、target.path、result.runtime_result 时，
        # 无法做权限和路径判断，应判定为 invalid_input。
        result = detect_record([make_policy(), {"request": {}, "target": {}, "result": {}}])

        self.assertEqual(result["detection"]["status"], STATUS_INVALID_INPUT)
        self.assertTrue(
            any("missing kernel event fields" in reason for reason in result["detection"]["reasons"])
        )

    def test_unsupported_policy(self):
        # 覆盖不支持的策略类型：
        # 当前检测模块只处理 resource_type=file 且 effect=allow 的策略。
        result = detect_record([make_policy(resource_type="tool"), make_event()])

        self.assertEqual(result["detection"]["status"], STATUS_UNSUPPORTED_POLICY)
        self.assertIn("only file allow policies are supported", result["detection"]["reasons"])

    def test_detect_stream_handles_bad_json(self):
        # 覆盖 NDJSON 流式读取中的坏行：
        # 单行 JSON 解析失败时，不抛出异常中断整个流，而是输出 invalid_input。
        results = list(detect_stream(["not json\n"]))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["detection"]["status"], STATUS_INVALID_INPUT)
        self.assertTrue(results[0]["detection"]["reasons"][0].startswith("line 1: invalid json"))

    def test_writes_detection_log_for_review(self):
        # 覆盖日志落盘：
        # 单元测试运行后会生成 detection/test/file_anomaly_events.test.ndjson，
        # 里面包含 normal、permission_exceeded、resource_out_of_scope 等典型输出。
        records = [
            [make_policy(), make_event()],
            [make_policy(), make_event(request_perm="exec")],
            [make_policy(), make_event(target_path="/etc/hosts")],
            [make_policy(), make_event(request_perm="exec", runtime_result="deny")],
            [make_policy(), make_event(request_perm="exec", runtime_result="error")],
            {"not": "a correlated record"},
            [make_policy(), {"request": {}, "target": {}, "result": {}}],
            [make_policy(resource_type="tool"), make_event()],
        ]

        write_detection_log(records, TEST_LOG_PATH)

        self.assertTrue(os.path.exists(TEST_LOG_PATH))
        with open(TEST_LOG_PATH, "r", encoding="utf-8") as log_file:
            results = [json.loads(line) for line in log_file if line.strip()]

        statuses = [result["detection"]["status"] for result in results]
        self.assertEqual(
            statuses,
            [
                STATUS_NORMAL,
                STATUS_PERMISSION_EXCEEDED,
                STATUS_RESOURCE_OUT_OF_SCOPE,
                STATUS_BLOCKED_VIOLATION_ATTEMPT,
                STATUS_RUNTIME_ERROR,
                STATUS_INVALID_INPUT,
                STATUS_INVALID_INPUT,
                STATUS_UNSUPPORTED_POLICY,
            ],
        )


if __name__ == "__main__":
    unittest.main()
