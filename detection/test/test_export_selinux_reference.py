import unittest

from detection.export_selinux_reference import (
    build_expected_domains,
    build_reference,
    parse_allow_rules,
    parse_fcontext_list,
    parse_type_transitions,
)


# Sample of `semanage fcontext -l` output, including header, an equivalence
# line, a <<none>> entry, and the local-customisation section header.
FCONTEXT_SAMPLE = """\
SELinux fcontext                                   type               Context

/.*                                                all files          system_u:object_r:default_t:s0
/usr/sbin/httpd                                    regular file       system_u:object_r:httpd_exec_t:s0
/var/www(/.*)?                                     all files          system_u:object_r:httpd_sys_content_t:s0
/var/www/private(/.*)?                             all files          system_u:object_r:httpd_private_content_t:s0
/srv/nostick                                       regular file       <<none>>

SELinux Local fcontext Equivalence

/var/mail = /var/spool/mail
"""

# Sample of `sesearch --type_trans` output, mixing spaced and compact colons,
# a non-process transition, and a named-file transition.
TYPE_TRANS_SAMPLE = """\
type_transition init_t httpd_exec_t:process httpd_t;
type_transition init_t sshd_exec_t : process sshd_t;
type_transition httpd_t httpd_var_run_t:dir httpd_var_run_t;
type_transition httpd_t httpd_log_t:file httpd_log_t "access.log";
"""

# Sample of `sesearch --allow` output, both brace and single-perm forms.
ALLOW_SAMPLE = """\
allow httpd_t httpd_sys_content_t:file { getattr ioctl lock open read };
allow httpd_t httpd_sys_content_t:dir search;
allow httpd_t httpd_sys_content_t : file write;
allowxperm httpd_t self:tcp_socket ioctl { 0x8910 };
"""


class FcontextParseTest(unittest.TestCase):
    def test_parses_data_rows_only(self):
        # 覆盖 file_contexts 解析：跳过表头、等价行、<<none>>，只保留 pattern->type。
        entries = parse_fcontext_list(FCONTEXT_SAMPLE)
        as_map = {e["pattern"]: e["type"] for e in entries}

        self.assertEqual(as_map["/usr/sbin/httpd"], "httpd_exec_t")
        self.assertEqual(as_map["/var/www(/.*)?"], "httpd_sys_content_t")
        self.assertEqual(as_map["/var/www/private(/.*)?"], "httpd_private_content_t")
        self.assertNotIn("/srv/nostick", as_map)  # <<none>>
        self.assertNotIn("/var/mail", as_map)  # equivalence line


class TypeTransParseTest(unittest.TestCase):
    def test_parses_both_colon_spacings(self):
        # 覆盖 type_transition 解析：兼容紧凑/带空格冒号，保留 class 与 default。
        records = parse_type_transitions(TYPE_TRANS_SAMPLE)
        process = {r["target"]: r["default"] for r in records if r["class"] == "process"}

        self.assertEqual(process["httpd_exec_t"], "httpd_t")
        self.assertEqual(process["sshd_exec_t"], "sshd_t")
        # 非 process 与 named-file 转换仍被记录，但 class 不是 process。
        classes = {r["class"] for r in records}
        self.assertIn("dir", classes)
        self.assertIn("file", classes)


class AllowParseTest(unittest.TestCase):
    def test_parses_brace_and_single_perm(self):
        # 覆盖 allow 解析：花括号多权限与单权限都能解析，allowxperm 被忽略。
        rules = parse_allow_rules(ALLOW_SAMPLE)

        file_rule = next(r for r in rules if r["class"] == "file" and "read" in r["perms"])
        self.assertEqual(file_rule["source"], "httpd_t")
        self.assertEqual(file_rule["target"], "httpd_sys_content_t")
        self.assertIn("open", file_rule["perms"])

        dir_rule = next(r for r in rules if r["class"] == "dir")
        self.assertEqual(dir_rule["perms"], ["search"])

        # spaced-colon single perm form
        self.assertTrue(any(r["class"] == "file" and r["perms"] == ["write"] for r in rules))
        # allowxperm must be ignored
        self.assertFalse(any(r["class"] == "tcp_socket" for r in rules))


class ExpectedDomainsTest(unittest.TestCase):
    def test_derives_comm_to_domain_from_literal_exec_paths(self):
        # 覆盖 expected_domains 推导：process 转换的 exec type 经 file_contexts
        # 反查到字面路径，basename 作为 comm，default 域作为期望域。
        fcontexts = parse_fcontext_list(FCONTEXT_SAMPLE)
        transitions = parse_type_transitions(TYPE_TRANS_SAMPLE)
        domains = build_expected_domains(transitions, fcontexts)

        # /usr/sbin/httpd is httpd_exec_t, which transitions to httpd_t
        self.assertEqual(domains["httpd"], "httpd_t")

    def test_skips_regex_exec_patterns(self):
        # 覆盖只接受字面路径：含正则元字符的 pattern 不会被反推成 comm。
        fcontexts = [{"pattern": "/usr/sbin/http.*", "type": "httpd_exec_t"}]
        transitions = [{"source": "init_t", "target": "httpd_exec_t", "class": "process", "default": "httpd_t"}]
        domains = build_expected_domains(transitions, fcontexts)
        self.assertEqual(domains, {})

    def test_skips_conflicting_comms(self):
        # 覆盖冲突丢弃：同名 comm 指向不同域时整体丢弃，避免给出错误的高置信结论。
        fcontexts = [
            {"pattern": "/opt/a/run", "type": "a_exec_t"},
            {"pattern": "/opt/b/run", "type": "b_exec_t"},
        ]
        transitions = [
            {"source": "init_t", "target": "a_exec_t", "class": "process", "default": "a_t"},
            {"source": "init_t", "target": "b_exec_t", "class": "process", "default": "b_t"},
        ]
        domains = build_expected_domains(transitions, fcontexts)
        self.assertNotIn("run", domains)


class BuildReferenceTest(unittest.TestCase):
    def test_assembles_all_three_tables(self):
        # 覆盖整体组装：三段命令输出拼成分类器可直接消费的参考对象。
        reference = build_reference(FCONTEXT_SAMPLE, TYPE_TRANS_SAMPLE, ALLOW_SAMPLE)

        self.assertIn("file_contexts", reference)
        self.assertEqual(reference["expected_domains"]["httpd"], "httpd_t")
        self.assertTrue(len(reference["allow_rules"]) >= 1)

    def test_no_allow_omits_allow_rules(self):
        # 覆盖 --no-allow：allow_text 为 None 时不输出 allow_rules 表。
        reference = build_reference(FCONTEXT_SAMPLE, TYPE_TRANS_SAMPLE, None)
        self.assertNotIn("allow_rules", reference)


if __name__ == "__main__":
    unittest.main()
