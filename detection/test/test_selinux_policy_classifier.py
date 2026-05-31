import json
import os
import unittest

from detection.file_anomaly_detector import detect_record
from detection.selinux_policy_classifier import (
    CATEGORY_NOT_APPLICABLE,
    CATEGORY_PCI,
    CATEGORY_POLICY_CORRECT,
    CATEGORY_TMM,
    CATEGORY_TTLP,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    classify_detection,
    classify_stream,
    context_type,
    write_classification_log,
)


TEST_DIR = os.path.dirname(__file__)
TEST_LOG_PATH = os.path.join(TEST_DIR, "selinux_classification_events.test.ndjson")


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
        elif key == "tcontext":
            event["target"]["tcontext"] = value
        elif key == "scontext":
            event["subject"]["scontext"] = value
        elif key == "comm":
            event["subject"]["comm"] = value
        elif key == "runtime_result":
            event["result"]["runtime_result"] = value
        else:
            event[key] = value
    return event


def detection_for(policy, event):
    """Run the first stage so the classifier consumes realistic input."""
    return detect_record([policy, event])


class ContextTypeTest(unittest.TestCase):
    def test_extracts_type_field(self):
        # 覆盖 context type 抽取：取冒号分隔的第 3 段。
        self.assertEqual(
            context_type("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"),
            "unconfined_t",
        )
        self.assertEqual(context_type("system_u:object_r:user_home_t:s0"), "user_home_t")

    def test_handles_malformed_context(self):
        # 覆盖异常 context：字段不足或非字符串时返回 None。
        self.assertIsNone(context_type("only:two"))
        self.assertIsNone(context_type(None))
        self.assertIsNone(context_type(123))


class ClassifyWithReferenceTest(unittest.TestCase):
    def test_tmm_object_label_mismatch(self):
        # 覆盖 TMM：权限越界且客体实际 type 与参考 file_contexts 期望不一致，
        # 判定为标签错误，修复建议为 relabel。
        reference = {
            "file_contexts": [
                {"pattern": r"/workspace/outputs(/.*)?", "type": "workspace_output_t"},
            ],
        }
        detection = detection_for(make_policy(), make_event(request_perm="exec"))
        result = classify_detection(detection, reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TMM)
        self.assertEqual(cls["confidence"], CONFIDENCE_HIGH)
        self.assertEqual(cls["expected"]["T"], "workspace_output_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "relabel")
        self.assertIn("workspace_output_t", cls["recommended_fix"]["command"])

    def test_ttlp_subject_domain_mismatch(self):
        # 覆盖 TTLP：客体标签与参考一致（跳过 TMM），但主体域不是参考期望的
        # 受限域，判定为域转换错误，修复建议为 type_transition。
        reference = {
            "file_contexts": [
                {"pattern": r"/workspace/outputs(/.*)?", "type": "user_home_t"},
            ],
            "expected_domains": {"tee": "tee_t"},
        }
        detection = detection_for(make_policy(), make_event(request_perm="exec"))
        result = classify_detection(detection, reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TTLP)
        self.assertEqual(cls["confidence"], CONFIDENCE_HIGH)
        self.assertEqual(cls["expected"]["S"], "tee_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "type_transition")

    def test_pci_labels_match_allow_rule_too_permissive(self):
        # 覆盖 PCI：客体标签和主体域都与参考一致，却仍放行，
        # 命中过宽的 allow 规则，修复建议为删除该权限。
        reference = {
            "file_contexts": [
                {"pattern": r"/workspace/outputs(/.*)?", "type": "user_home_t"},
            ],
            "expected_domains": {"tee": "unconfined_t"},
            "allow_rules": [
                {
                    "source": "unconfined_t",
                    "target": "user_home_t",
                    "class": "file",
                    "perms": ["execute", "read"],
                },
            ],
        }
        detection = detection_for(make_policy(), make_event(request_perm="exec"))
        result = classify_detection(detection, reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_PCI)
        self.assertEqual(cls["confidence"], CONFIDENCE_HIGH)
        self.assertEqual(cls["recommended_fix"]["kind"], "remove_allow")
        self.assertTrue(any("allow unconfined_t user_home_t:file" in e for e in cls["evidence"]))

    def test_resource_out_of_scope_is_classified(self):
        # 覆盖 resource_out_of_scope 也能归因：路径越界时，整次访问非法，
        # 客体标签与参考不一致仍判为 TMM。
        reference = {
            "file_contexts": [
                {"pattern": r"/etc/shadow", "type": "shadow_t"},
            ],
        }
        detection = detection_for(make_policy(), make_event(target_path="/etc/shadow"))
        result = classify_detection(detection, reference)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TMM)
        self.assertEqual(cls["expected"]["T"], "shadow_t")


class ClassifyHeuristicTest(unittest.TestCase):
    def test_heuristic_tmm_generic_object_type(self):
        # 覆盖无参考表降级：客体 type 为通用类型（user_home_t），
        # 启发式猜测为 TMM 且置信度 low。
        detection = detection_for(make_policy(), make_event(request_perm="exec"))
        result = classify_detection(detection, reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TMM)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)

    def test_heuristic_ttlp_broad_subject_domain(self):
        # 覆盖无参考表降级：客体 type 非通用、主体域为宽泛域（unconfined_t），
        # 启发式猜测为 TTLP 且置信度 low。
        detection = detection_for(
            make_policy(),
            make_event(
                request_perm="exec",
                tcontext="system_u:object_r:httpd_private_content_t:s0",
            ),
        )
        result = classify_detection(detection, reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_TTLP)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)

    def test_heuristic_pci_specific_labels(self):
        # 覆盖无参考表降级：客体 type 非通用、主体域非宽泛，
        # 启发式猜测为 PCI 且置信度 low。
        detection = detection_for(
            make_policy(),
            make_event(
                request_perm="exec",
                tcontext="system_u:object_r:httpd_private_content_t:s0",
                scontext="system_u:system_r:httpd_t:s0",
            ),
        )
        result = classify_detection(detection, reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_PCI)
        self.assertEqual(cls["confidence"], CONFIDENCE_LOW)


class ClassifyNonViolationTest(unittest.TestCase):
    def test_blocked_violation_is_policy_correct(self):
        # 覆盖 policy_correct：内核已 deny 的越权尝试，策略本身正确，不需调整。
        detection = detection_for(
            make_policy(),
            make_event(request_perm="exec", runtime_result="deny"),
        )
        result = classify_detection(detection, reference=None)

        self.assertEqual(result["selinux_classification"]["category"], CATEGORY_POLICY_CORRECT)

    def test_normal_record_is_not_applicable(self):
        # 覆盖 not_applicable：正常访问不进入策略归因。
        detection = detection_for(make_policy(), make_event())
        result = classify_detection(detection, reference=None)

        self.assertEqual(result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE)

    def test_non_dict_input_is_not_applicable(self):
        # 覆盖非法输入：非 detection 结果对象时标记 not_applicable。
        result = classify_detection(["not", "a", "detection"], reference=None)
        self.assertEqual(result["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE)

    def test_permissive_runtime_allow_but_policy_deny_is_policy_correct(self):
        # 覆盖 permissive 模式：runtime_result=allow 但 policy_result=deny，
        # 说明策略其实拒绝了（只是 permissive 未强制执行），不应归因为策略错误。
        event = make_event(request_perm="exec")
        event["result"]["runtime_result"] = "allow"
        event["result"]["policy_result"] = "deny"
        result = classify_detection(detection_for(make_policy(), event), reference=None)

        cls = result["selinux_classification"]
        self.assertEqual(cls["category"], CATEGORY_POLICY_CORRECT)
        self.assertTrue(any("permissive" in e for e in cls["evidence"]))


class ClassifyStreamTest(unittest.TestCase):
    def test_stream_handles_bad_json(self):
        # 覆盖 NDJSON 坏行：单行解析失败时标记 not_applicable，不中断流。
        results = list(classify_stream(["not json\n"]))

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["selinux_classification"]["category"], CATEGORY_NOT_APPLICABLE
        )

    def test_writes_classification_log_for_review(self):
        # 覆盖日志落盘：用同一份参考表驱动 5 行（不同 in-scope 路径），
        # 生成 selinux_classification_events.test.ndjson，
        # 包含 TMM/TTLP/PCI/policy_correct/not_applicable 五类典型输出。
        reference = {
            "file_contexts": [
                {"pattern": r"/workspace/outputs/a", "type": "workspace_output_t"},
                {"pattern": r"/workspace/outputs/b", "type": "user_home_t"},
                {"pattern": r"/workspace/outputs/c", "type": "user_home_t"},
            ],
            "expected_domains": {"tee": "tee_t", "cat": "unconfined_t"},
            "allow_rules": [
                {"source": "unconfined_t", "target": "user_home_t", "class": "file", "perms": ["execute"]},
            ],
        }

        # TMM: object label mismatch on /a
        tmm = detection_for(make_policy(), make_event(request_perm="exec", target_path="/workspace/outputs/a"))
        # TTLP: label matches on /b, comm tee should be tee_t but runs unconfined_t
        ttlp = detection_for(make_policy(), make_event(request_perm="exec", target_path="/workspace/outputs/b", comm="tee"))
        # PCI: label and domain match on /c, allow rule grants execute
        pci = detection_for(make_policy(), make_event(request_perm="exec", target_path="/workspace/outputs/c", comm="cat"))
        # policy_correct: kernel denied the violation
        denied = detection_for(make_policy(), make_event(request_perm="exec", runtime_result="deny"))
        # not_applicable: normal access
        normal = detection_for(make_policy(), make_event())

        write_classification_log([tmm, ttlp, pci, denied, normal], TEST_LOG_PATH, reference=reference)

        self.assertTrue(os.path.exists(TEST_LOG_PATH))
        with open(TEST_LOG_PATH, "r", encoding="utf-8") as log_file:
            logged = [json.loads(line) for line in log_file if line.strip()]

        categories = [item["selinux_classification"]["category"] for item in logged]
        self.assertEqual(
            categories,
            [
                CATEGORY_TMM,
                CATEGORY_TTLP,
                CATEGORY_PCI,
                CATEGORY_POLICY_CORRECT,
                CATEGORY_NOT_APPLICABLE,
            ],
        )


if __name__ == "__main__":
    unittest.main()
