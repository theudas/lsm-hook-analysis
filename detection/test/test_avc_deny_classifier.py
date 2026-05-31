import json
import os
import unittest

from detection.avc_deny_classifier import (
    CATEGORY_MISSING_ALLOW,
    CATEGORY_UNDETERMINED,
    classify_avc_deny,
    classify_avc_stream,
    write_avc_classification_log,
)
from detection.selinux_policy_classifier import (
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_POLICY_CORRECT,
    CATEGORY_TMM,
    CATEGORY_TTLP,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
)


TEST_DIR = os.path.dirname(__file__)
TEST_LOG_PATH = os.path.join(TEST_DIR, "avc_deny_classification_events.test.ndjson")


def make_policy(**overrides):
    policy = {
        "policy_ref": "policies[1]",
        "subject": "file",
        "effect": "allow",
        "resource_type": "file",
        "identifier": "/var/www/private/**",
        "normalized_prefix": "/var/www/private/",
        "actions": ["read"],
    }
    policy.update(overrides)
    return policy


def make_avc(**overrides):
    avc = {
        "timestamp_ns": 1778482476753106527,
        "scontext": "system_u:system_r:httpd_t:s0",
        "tcontext": "system_u:object_r:httpd_private_content_t:s0",
        "tclass": "file",
        "perm": "open|read",
        "pid": 1234,
        "tid": 1234,
        "comm": "httpd",
        "permissive": 0,
        "denied": 1,
    }
    avc.update(overrides)
    return avc


class AvcDenyWithReferenceTest(unittest.TestCase):
    def test_tmm_object_mislabel_blocks_access(self):
        # 覆盖 deny 方向 TMM：合法读取被拒，客体实际 type 与期望不符，
        # 说明文件标签错了，修复为 relabel。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
        }
        # 实际标签错成了 default_t
        avc = make_avc(tcontext="system_u:object_r:default_t:s0")
        result = classify_avc_deny([make_policy(), avc], reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TMM)
        self.assertEqual(cls["direction"], "deny")
        self.assertEqual(cls["confidence"], CONFIDENCE_HIGH)
        self.assertEqual(cls["expected"]["T"], "httpd_private_content_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "relabel")

    def test_ttlp_wrong_subject_domain(self):
        # 覆盖 deny 方向 TTLP：客体标签对，但进程域不是期望受限域，
        # 缺少应有权限，修复为补类型转换。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
            "expected_domains": {"httpd": "httpd_t"},
        }
        avc = make_avc(scontext="system_u:system_r:init_t:s0")
        result = classify_avc_deny([make_policy(), avc], reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TTLP)
        self.assertEqual(cls["expected"]["S"], "httpd_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "type_transition")

    def test_missing_allow_rule(self):
        # 覆盖 deny 方向 missing_allow：标签和域都对，但参考表里没有授予该权限的
        # allow 规则，修复为新增 allow 规则。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
            "expected_domains": {"httpd": "httpd_t"},
            "allow_rules": [
                {"source": "httpd_t", "target": "httpd_private_content_t", "class": "file", "perms": ["getattr"]},
            ],
        }
        result = classify_avc_deny([make_policy(), make_avc()], reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_MISSING_ALLOW)
        self.assertEqual(cls["recommended_fix"]["kind"], "add_allow")
        self.assertIn("read", cls["recommended_fix"]["command"])

    def test_undetermined_when_rule_exists_but_denied(self):
        # 覆盖 undetermined：allow 规则存在却仍被拒，根因在三机制之外
        # （boolean/MLS/约束等），低置信度且不给确定修复。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
            "expected_domains": {"httpd": "httpd_t"},
            "allow_rules": [
                {"source": "httpd_t", "target": "httpd_private_content_t", "class": "file", "perms": ["read", "open"]},
            ],
        }
        result = classify_avc_deny([make_policy(), make_avc()], reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_UNDETERMINED)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)
        self.assertNotIn("recommended_fix", cls)

    def test_permissive_note_is_attached(self):
        # 覆盖 permissive 标注：permissive 模式下 deny 未被强制执行，
        # 证据中应给出对 enforcing 模式的预警，但仍照常归因。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
            "expected_domains": {"httpd": "httpd_t"},
            "allow_rules": [],
        }
        result = classify_avc_deny([make_policy(), make_avc(permissive=1)], reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_MISSING_ALLOW)
        self.assertTrue(any("permissive mode" in e for e in cls["evidence"]))


class AvcDenyHeuristicTest(unittest.TestCase):
    def test_heuristic_tmm_generic_object_type(self):
        # 覆盖无参考表降级：客体 type 为通用类型，启发式猜 TMM、置信度 low。
        avc = make_avc(tcontext="system_u:object_r:default_t:s0")
        result = classify_avc_deny([make_policy(), avc], reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TMM)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)

    def test_heuristic_missing_allow_specific_labels(self):
        # 覆盖无参考表降级：标签具体，启发式猜 missing_allow、置信度 low。
        result = classify_avc_deny([make_policy(), make_avc()], reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_MISSING_ALLOW)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)


class AvcDenyApplicabilityTest(unittest.TestCase):
    def test_deny_outside_intended_actions_is_policy_correct(self):
        # 覆盖 policy_correct：被拒动作不在用户态 actions 内，SELinux 拒得对。
        # policy 只允许 read，但被拒的是 exec。
        result = classify_avc_deny([make_policy(), make_avc(perm="exec")], reference=None)

        self.assertEqual(
            result["selinux_classification"]["category"], CATEGORY_POLICY_CORRECT
        )

    def test_no_policy_is_not_applicable(self):
        # 覆盖 not_applicable：无可用关联 allow 策略时无法判断是否越界拦截。
        result = classify_avc_deny([None, make_avc()], reference=None)

        self.assertEqual(
            result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )

    def test_non_deny_event_is_not_applicable(self):
        # 覆盖 not_applicable：denied 未置位的事件不是 deny，不进入归因。
        result = classify_avc_deny([make_policy(), make_avc(denied=0)], reference=None)

        self.assertEqual(
            result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )

    def test_missing_avc_fields_is_not_applicable(self):
        # 覆盖 not_applicable：AVC 事件缺必要字段时标记 not_applicable。
        result = classify_avc_deny([make_policy(), {"denied": 1}], reference=None)

        self.assertEqual(
            result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )

    def test_bad_structure_is_not_applicable(self):
        # 覆盖 not_applicable：输入不是二元数组时标记 not_applicable。
        result = classify_avc_deny({"not": "a pair"}, reference=None)

        self.assertEqual(
            result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )


class AvcDenyStreamTest(unittest.TestCase):
    def test_stream_handles_bad_json(self):
        # 覆盖 NDJSON 坏行：单行解析失败标记 not_applicable，不中断流。
        results = list(classify_avc_stream(["not json\n"]))

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )

    def test_writes_classification_log_for_review(self):
        # 覆盖日志落盘：一份参考表驱动多类典型 deny 输出并持久化。
        reference = {
            "file_contexts": [
                {"pattern": r"/var/www/private(/.*)?", "type": "httpd_private_content_t"},
            ],
            "expected_domains": {"httpd": "httpd_t"},
            "allow_rules": [
                {"source": "httpd_t", "target": "httpd_private_content_t", "class": "file", "perms": ["getattr"]},
            ],
        }
        records = [
            [make_policy(), make_avc(tcontext="system_u:object_r:default_t:s0")],  # TMM
            [make_policy(), make_avc(scontext="system_u:system_r:init_t:s0")],     # TTLP
            [make_policy(), make_avc()],                                            # missing_allow
            [make_policy(), make_avc(perm="exec")],                                 # policy_correct
            [None, make_avc()],                                                     # not_applicable
        ]

        write_avc_classification_log(records, TEST_LOG_PATH, reference=reference)

        self.assertTrue(os.path.exists(TEST_LOG_PATH))
        with open(TEST_LOG_PATH, "r", encoding="utf-8") as log_file:
            logged = [json.loads(line) for line in log_file if line.strip()]

        categories = [item["selinux_classification"]["category"] for item in logged]
        self.assertEqual(
            categories,
            [
                CATEGORY_TMM,
                CATEGORY_TTLP,
                CATEGORY_MISSING_ALLOW,
                CATEGORY_POLICY_CORRECT,
                CATEGORY_NOT_APPLICABLE,
            ],
        )


if __name__ == "__main__":
    unittest.main()
