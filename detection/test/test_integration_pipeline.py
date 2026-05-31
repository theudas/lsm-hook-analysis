"""End-to-end integration test for the SELinux detection pipeline.

This test exercises the full chain exactly as it runs in production:

    1. Host policy export   raw `semanage`/`sesearch` text
                              -> export_selinux_reference.build_reference()
                              -> the three reference tables
                                 (file_contexts / expected_domains / allow_rules)

    2. Correlated record    [user-space IR policy, kernel-state event]
                              -> file_anomaly_detector.detect_record()   (allow direction)
                              -> selinux_policy_classifier.classify_detection()

    3. Correlated AVC deny  [user-space IR policy, avc_event]
                              -> avc_deny_classifier.classify_avc_deny()  (deny direction)

The scenario is a web server (`httpd`, should run as `httpd_t`) and an
in-house service (`appd`, should run as `appd_t`).  The reference is *derived
from* the sample host-command output below -- nothing is hand-written -- so
the test also documents where each reference table comes from.
"""

import unittest

from detection.export_selinux_reference import build_reference
from detection.file_anomaly_detector import detect_record
from detection.selinux_policy_classifier import classify_detection
from detection.avc_deny_classifier import classify_avc_deny


# ---------------------------------------------------------------------------
# 1. Provenance of the reference tables: raw host-command output.
#
#    file_contexts    <- `semanage fcontext -l`
#    expected_domains <- `sesearch --type_trans` resolved through file_contexts
#    allow_rules      <- `sesearch --allow -c file`
# ---------------------------------------------------------------------------

RAW_FCONTEXT = """\
SELinux fcontext                                   type               Context

/var/www/html(/.*)?                                all files          system_u:object_r:httpd_sys_content_t:s0
/var/www/private(/.*)?                             all files          system_u:object_r:httpd_private_content_t:s0
/opt/app/data(/.*)?                                all files          system_u:object_r:appd_data_t:s0
/usr/sbin/httpd                                    regular file       system_u:object_r:httpd_exec_t:s0
/opt/app/bin/appd                                  regular file       system_u:object_r:appd_exec_t:s0
"""

RAW_TYPE_TRANS = """\
type_transition init_t httpd_exec_t:process httpd_t;
type_transition init_t appd_exec_t:process appd_t;
"""

# NOTE: 'write' on httpd_sys_content_t is over-permissive on purpose (drives an
# allow-direction PCI finding); appd_data_t has no 'write' (drives a
# deny-direction missing_allow finding).
RAW_ALLOW = """\
allow httpd_t httpd_sys_content_t:file { read open getattr write };
allow httpd_t httpd_private_content_t:file { read open getattr };
allow appd_t appd_data_t:file { read open getattr };
"""


def policy(prefix, actions, identifier=None):
    """A normalized user-space IR file policy (the 'allowed scope' oracle)."""
    return {
        "policy_ref": "policies[1]",
        "subject": "file",
        "effect": "allow",
        "resource_type": "file",
        "identifier": identifier or (prefix + "**"),
        "normalized_prefix": prefix,
        "actions": actions,
    }


def kernel_event(comm, scontext, perm, path, tcontext, runtime, tclass="file"):
    """A kernel-state file event as produced by the resolver/capture path."""
    return {
        "hook": "selinux_file_open",
        "hook_signature": "static int selinux_file_open(struct file *file)",
        "timestamp_ns": 1778482476753106527,
        "subject": {"pid": 1, "tid": 1, "scontext": scontext, "comm": comm},
        "request": {"mask_raw": 0, "obj_type": "reg", "perm": perm},
        "target": {
            "dev": "dm-0",
            "ino": 1,
            "type": "reg",
            "path": path,
            "tclass": tclass,
            "tcontext": tcontext,
        },
        "result": {"ret": 0, "runtime_result": runtime, "policy_result": "inferred_allow"},
    }


def avc_event(scontext, tcontext, perm, comm, denied=1, permissive=0, tclass="file"):
    """An AVC deny event (user-space form of struct lha_avc_event_v1)."""
    return {
        "timestamp_ns": 1778482476753106527,
        "scontext": scontext,
        "tcontext": tcontext,
        "tclass": tclass,
        "perm": perm,
        "pid": 1,
        "tid": 1,
        "comm": comm,
        "permissive": permissive,
        "denied": denied,
    }


class PipelineIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Stage 1: derive the three reference tables from raw host output.
        cls.reference = build_reference(RAW_FCONTEXT, RAW_TYPE_TRANS, RAW_ALLOW)

    # -- Stage 1: the reference tables are obtained, not hand-written --------

    def test_file_contexts_derived_from_semanage(self):
        # file_contexts 来自 `semanage fcontext -l`：路径正则 -> 期望 type。
        fc = {e["pattern"]: e["type"] for e in self.reference["file_contexts"]}
        self.assertEqual(fc["/var/www/private(/.*)?"], "httpd_private_content_t")
        self.assertEqual(fc["/opt/app/data(/.*)?"], "appd_data_t")

    def test_expected_domains_derived_from_type_trans_and_fcontext(self):
        # expected_domains 来自 `sesearch --type_trans`：process 转换的 exec type
        # 经 file_contexts 反查字面路径 -> basename(comm) -> 目标域。
        self.assertEqual(
            self.reference["expected_domains"],
            {"httpd": "httpd_t", "appd": "appd_t"},
        )

    def test_allow_rules_derived_from_sesearch(self):
        # allow_rules 来自 `sesearch --allow`：(源域, 客体type, 安全类) -> 权限集合。
        httpd_html = next(
            r for r in self.reference["allow_rules"]
            if r["source"] == "httpd_t" and r["target"] == "httpd_sys_content_t"
        )
        self.assertIn("write", httpd_html["perms"])  # 过宽的 write
        appd_data = next(
            r for r in self.reference["allow_rules"]
            if r["source"] == "appd_t" and r["target"] == "appd_data_t"
        )
        self.assertNotIn("write", appd_data["perms"])  # 缺 write

    # -- Stage 2: allow direction (kernel event + IR -> detect -> classify) --

    def _classify_allow(self, record):
        detection = detect_record(record)
        result = classify_detection(detection, self.reference)
        return detection["detection"]["status"], result["selinux_classification"]

    def test_allow_normal_is_not_applicable(self):
        # 正常读：在范围内、权限被覆盖 -> detector normal -> 不进入归因。
        status, cls = self._classify_allow([
            policy("/var/www/html/", ["read"]),
            kernel_event("httpd", "system_u:system_r:httpd_t:s0", "open|read",
                         "/var/www/html/index.html",
                         "system_u:object_r:httpd_sys_content_t:s0", "allow"),
        ])
        self.assertEqual(status, "normal")
        self.assertEqual(cls["category"], "not_applicable")
        self.assertEqual(cls["direction"], "allow")

    def test_allow_pci_over_permissive_rule(self):
        # 越权写且 allow 规则确实授予 write、标签与域都对 -> PCI（删规则）。
        status, cls = self._classify_allow([
            policy("/var/www/html/", ["read"]),
            kernel_event("httpd", "system_u:system_r:httpd_t:s0", "write",
                         "/var/www/html/index.html",
                         "system_u:object_r:httpd_sys_content_t:s0", "allow"),
        ])
        self.assertEqual(status, "permission_exceeded")
        self.assertEqual(cls["category"], "PCI")
        self.assertEqual(cls["confidence"], "high")
        self.assertEqual(cls["recommended_fix"]["kind"], "remove_allow")

    def test_allow_tmm_mislabeled_resource(self):
        # 越界读到一个被错打成 html 标签的 private 文件 -> TMM（relabel）。
        status, cls = self._classify_allow([
            policy("/var/www/html/", ["read"]),
            kernel_event("httpd", "system_u:system_r:httpd_t:s0", "open|read",
                         "/var/www/private/secret",
                         "system_u:object_r:httpd_sys_content_t:s0", "allow"),
        ])
        self.assertEqual(status, "resource_out_of_scope")
        self.assertEqual(cls["category"], "TMM")
        self.assertEqual(cls["expected"]["T"], "httpd_private_content_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "relabel")

    def test_allow_ttlp_untransitioned_process(self):
        # appd 本应是 appd_t 却跑在 unconfined_t（未转换），越权写 -> TTLP（补转换）。
        status, cls = self._classify_allow([
            policy("/opt/app/data/", ["read"]),
            kernel_event("appd", "system_u:system_r:unconfined_t:s0", "write",
                         "/opt/app/data/db",
                         "system_u:object_r:appd_data_t:s0", "allow"),
        ])
        self.assertEqual(status, "permission_exceeded")
        self.assertEqual(cls["category"], "TTLP")
        self.assertEqual(cls["expected"]["S"], "appd_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "type_transition")

    def test_allow_blocked_attempt_is_policy_correct(self):
        # 越权 exec 被内核 deny -> policy_correct（策略本身没问题）。
        status, cls = self._classify_allow([
            policy("/var/www/html/", ["read"]),
            kernel_event("httpd", "system_u:system_r:httpd_t:s0", "exec",
                         "/var/www/html/cgi",
                         "system_u:object_r:httpd_sys_content_t:s0", "deny"),
        ])
        self.assertEqual(status, "blocked_violation_attempt")
        self.assertEqual(cls["category"], "policy_correct")

    # -- Stage 3: deny direction (avc event + IR -> classify) ----------------

    def _classify_deny(self, record):
        return classify_avc_deny(record, self.reference)["selinux_classification"]

    def test_deny_tmm_mislabeled_resource(self):
        # 合法读被拒，文件被错打成 default_t -> TMM（relabel 回 appd_data_t）。
        cls = self._classify_deny([
            policy("/opt/app/data/", ["read"]),
            avc_event("system_u:system_r:appd_t:s0",
                      "system_u:object_r:default_t:s0", "open|read", "appd"),
        ])
        self.assertEqual(cls["category"], "TMM")
        self.assertEqual(cls["direction"], "deny")
        self.assertEqual(cls["expected"]["T"], "appd_data_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "relabel")

    def test_deny_ttlp_wrong_domain(self):
        # 合法读被拒，进程跑在 init_t 而非 httpd_t -> TTLP（补转换）。
        cls = self._classify_deny([
            policy("/var/www/private/", ["read"]),
            avc_event("system_u:system_r:init_t:s0",
                      "system_u:object_r:httpd_private_content_t:s0", "read", "httpd"),
        ])
        self.assertEqual(cls["category"], "TTLP")
        self.assertEqual(cls["expected"]["S"], "httpd_t")
        self.assertEqual(cls["recommended_fix"]["kind"], "type_transition")

    def test_deny_missing_allow_rule(self):
        # 合法写被拒，标签与域都对但 allow 规则缺 write -> missing_allow（加规则）。
        cls = self._classify_deny([
            policy("/opt/app/data/", ["write"]),
            avc_event("system_u:system_r:appd_t:s0",
                      "system_u:object_r:appd_data_t:s0", "write", "appd"),
        ])
        self.assertEqual(cls["category"], "missing_allow")
        self.assertEqual(cls["recommended_fix"]["kind"], "add_allow")
        self.assertIn("write", cls["recommended_fix"]["command"])

    def test_deny_undetermined_with_permissive_note(self):
        # 合法读被拒，allow 规则却存在 -> undetermined；permissive 模式给出预警。
        cls = self._classify_deny([
            policy("/var/www/html/", ["read"]),
            avc_event("system_u:system_r:httpd_t:s0",
                      "system_u:object_r:httpd_sys_content_t:s0", "read", "httpd",
                      permissive=1),
        ])
        self.assertEqual(cls["category"], "undetermined")
        self.assertEqual(cls["confidence"], "low")
        self.assertNotIn("recommended_fix", cls)
        self.assertTrue(any("permissive mode" in e for e in cls["evidence"]))

    def test_deny_outside_intent_is_policy_correct(self):
        # exec 被拒、用户态本就没打算允许 -> policy_correct。
        cls = self._classify_deny([
            policy("/var/www/html/", ["read"]),
            avc_event("system_u:system_r:httpd_t:s0",
                      "system_u:object_r:httpd_sys_content_t:s0", "exec", "httpd"),
        ])
        self.assertEqual(cls["category"], "policy_correct")


if __name__ == "__main__":
    unittest.main()
