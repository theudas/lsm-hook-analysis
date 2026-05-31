# 检测原理总览：如何判定 SELinux 策略有误

本文从头到尾讲清楚本项目是**如何检测出 SELinux 策略配置错误**的：从内核态/用户态的数据
来源，到关联、检测、归因，最后给出可执行的策略修复建议。

相关模块与文档：

```text
detection/file_anomaly_detector.py        一阶段：行为是否偏离意图
detection/selinux_policy_classifier.py    二阶段（allow 方向）：定位是哪条策略
detection/avc_deny_classifier.py          二阶段（deny 方向）：定位是哪条策略
detection/export_selinux_reference.py     参考表导出：期望值的来源
detection/test/test_integration_pipeline.py  端到端集成测试
docs/file_anomaly_detection_design.md     一阶段详细设计
docs/selinux_policy_classification_design.md  二阶段详细设计（含 deny 方向 §10）
```

---

## 0. 核心判断逻辑：两个权威，一个矛盾

我们之所以敢断言"SELinux 策略错了"，**不是因为某个访问看起来可疑，而是因为两个相互独立
的权威对同一次访问给出了相互矛盾的结论**：

1. **用户态意图（IR oracle）**：归一化后的 file policy，表达"这个主体本来被允许对哪些资源
   做哪些操作"。

   ```text
   effect=allow, resource_type=file
   normalized_prefix=/var/www/html/      ← 允许的资源范围
   actions=[read]                        ← 允许的操作
   ```

2. **内核 SELinux 的策略裁决**：注意要区分内核态事件 `result` 里的两个字段：

   | 字段 | 含义 | 关键性质 |
   | --- | --- | --- |
   | `runtime_result` | 运行时**实际**发生的结果（allow/deny/error） | **permissive 模式下恒为 allow**，因为访问根本不会被拦 |
   | `policy_result` | SELinux **策略本身**的裁决（deny / inferred_allow / unknown） | 不受 enforcing/permissive 影响，是策略真正的判断 |

   **判断策略对不对，必须看 `policy_result`，不能看 `runtime_result`** —— 否则 permissive
   下"策略其实 deny 了、只是没强制执行"的情况会被误判成"策略放行了越权"。`runtime_result`
   只用来说明"这次越界行为是否真的在运行时发生了"。

SELinux 策略"对不对"的定义就是：**用户态意图与 `policy_result` 是否一致**。

| 用户态意图 | `policy_result` | 结论 |
| --- | --- | --- |
| 不允许 | inferred_allow | ❌ 策略太松：策略放行了越权 → **allow 方向异常** |
| 允许 | deny | ❌ 策略太紧：策略拦了合法访问 → **deny 方向异常** |
| 不允许 | deny | ✅ 策略拦得对 → `policy_correct`（即使 permissive 下 runtime 放行了） |
| 允许 | inferred_allow | ✅ 一致 → `normal` |

只有对角线那两格（矛盾）才是"策略有误"。检测的全部工作，就是**可靠地算出这张表的每一格，
并在异常时定位根因**。

> permissive 与 enforcing 的差别只体现在 `runtime_result`（是否真被拦），不改变
> `policy_result`（策略怎么判）。所以这张表在两种模式下都成立。

---

## 1. 数据从哪来：两条内核态采集 + 一条用户态 IR

### 1.1 内核态 —— LSM hook 事件（allow 方向的数据）

`lha_centos9_capture` 抓 LSM hook（如 `selinux_file_open`），经 resolver 结构化，通过 event
channel 送到用户态，最终是一条 `lha_event_payload_v1`：

```jsonc
{
  "hook": "selinux_file_open",
  "subject": { "comm": "httpd", "scontext": "system_u:system_r:httpd_t:s0" },
  "request": { "perm": "open|read" },                  // 内核真实请求的权限
  "target":  { "path": "/var/www/private/secret",
               "tclass": "file",
               "tcontext": "system_u:object_r:httpd_sys_content_t:s0" },
  "result":  { "ret": 0,
               "runtime_result": "allow",          // 运行时实际结果（permissive 下恒 allow）
               "policy_result": "inferred_allow" }  // ← SELinux 策略的真正裁决
}
```

关键：这条记录**同时带了主体标签 `scontext`、客体标签 `tcontext`、实际请求权限 `perm`、
运行时结果 `runtime_result` 和策略裁决 `policy_result`**。判断策略对错看 `policy_result`，
判断行为是否真的发生看 `runtime_result`；后面定位根因要用的标签信息也全在这里。

### 1.2 内核态 —— AVC deny 事件（deny 方向的数据）

`lha_centos9_avc_capture` 挂在 `selinux_audited` tracepoint 上，**只在 `denied != 0` 时触发**，
归一化成 `lha_avc_event_v1`：

```jsonc
{
  "scontext": "system_u:system_r:appd_t:s0",
  "tcontext": "system_u:object_r:default_t:s0",
  "tclass": "file", "perm": "open|read",
  "comm": "appd", "permissive": 0, "denied": 1
}
```

注意一个硬约束：**AVC deny 事件没有 path**（tracepoint 不带）。这决定了 deny 方向定位"客体
标签该是什么"时，资源路径只能从关联到的用户态 policy 里借。

### 1.3 用户态 —— IR policy（意图 oracle）

就是 §0 的那份归一化策略，描述"本应允许的范围 + 操作"，是判断对错的基准线。

---

## 2. 关联：把"内核实际发生"和"用户本来允许"对齐

上游关联模块把每条内核事件配上它落在的那条用户态 policy，产出二元组：

```text
[ 用户态 IR policy, 内核态事件 ]
```

这一步是后面一切的前提 —— **没有关联，就没有"意图 vs 实际"的对比对象**。allow 方向配 file
事件，deny 方向配 AVC 事件。

---

## 3. 第一阶段检测：行为是否偏离意图

`file_anomaly_detector` 输入关联二元组，回答两个纯粹的问题，**还不下"策略错"的结论**，只
判定"行为是否越界"。

**(a) 资源范围**：`target.path` 是否仍在 `normalized_prefix` 之下。

```text
/var/www/private/secret  startswith  /var/www/html/   →  False  → 越界
```

**(b) 权限覆盖**：把内核 `request.perm` 归一化到用户动作词表，再看是否被 `actions` 覆盖。

```text
归一化映射：open→read, read→read, write→write, append→write, exec→execute, search→read
exec → execute ；execute ∉ [read]  →  越权
```

**(c) 结合运行时结果 `runtime_result`**，落到一个状态：

| 状态 | 含义 | 行为是否实际越界 |
| --- | --- | --- |
| `normal` | 在范围内、权限被覆盖 | 否 |
| `permission_exceeded` | 权限越界，且 `runtime_result=allow` | 是（运行时确实发生） |
| `resource_out_of_scope` | 资源越界，且 `runtime_result=allow` | 是（运行时确实发生） |
| `blocked_violation_attempt` | 越界/越权，但 `runtime_result=deny` | 否（运行时被拦） |
| `runtime_error` / `invalid_input` / `unsupported_policy` | 异常态/不支持 | — |

注意：第一阶段用的是 `runtime_result`，回答的是**"越界行为是否在运行时真的发生了"（行为层
面）**，而**不是**"策略对不对"。permissive 模式下策略即使 deny，`runtime_result` 也是
allow，于是会落到 `permission_exceeded`/`resource_out_of_scope`。因此第二阶段在归因前会
**再用 `policy_result` 把这种情况甄别出来**（见 §6 步骤 ⓪），避免把"策略其实拒绝、只是没
强制执行"误判成策略错误。

到这里我们已经知道**"越界行为是否发生、以及方向"**，但还不知道**策略到底对不对、是哪条规则
造成的**。

---

## 4. 为什么"矛盾"就等于"SELinux 策略错" —— 而不是程序在作恶

这是最容易被质疑的一步，必须讲清楚：

- 内核态事件是 SELinux **已经按当前策略裁决完**的结果。`policy_result=inferred_allow`
  意味着"在当前这套 label + 规则下，SELinux 策略认为这次访问合法"（区别于 `runtime_result`，
  后者在 permissive 下恒为 allow，不代表策略真的放行）。
- 既然内核运转正常、策略也确实做出了 allow 裁决，那么一次"用户态明令禁止、策略却 allow"
  的访问，只可能源于两件事之一：**要么客体/主体的 label 不对（贴错了），要么策略规则授权
  太宽**。SPRT 论文 3.3 节即此意 —— 在内核正常、策略被执行的前提下，越权只能来自"标签错"
  或"规则配置不当"。
- 反过来，deny 方向"用户态允许、策略却 deny（AVC `denied==1`）"，同样只能是 label 错 或
  缺规则。

所以矛盾的根因被收敛到了 **SELinux 的三种策略机制**上 —— 这正好是第二阶段要分的三类。

---

## 5. 三种策略机制 = 三类根因（SPRT 形式化）

SELinux 决定一次访问，只用三种规则：

| 机制 | 形式化 | 决定了什么 | 出错表现 |
| --- | --- | --- | --- |
| 文件-标签映射 `r_f` | `Type → File` | 客体（文件）贴什么 type | 贴错 → **TMM 标签不对** |
| 类型转换 `r_t` | `<t_s, t_r, c, t_d>` | 进程 exec 后转换到哪个域 | 没转换/转错 → **TTLP 域转换错** |
| 类型强制 `r_e` | `<allow, d, t, c, {p}>` | 域 d 对 type t 有哪些权限 | 太宽 → **PCI**；太紧/缺 → **missing_allow** |

一次访问 = `允许(主体域 S, 客体 type T, 安全类 C, 权限 P)?`。S 由 `r_t` 决定，T 由 `r_f`
决定，能不能过由 `r_e` 决定。所以**任何裁决错误，必然落在这三者之一**。

---

## 6. 第二阶段定位：观测值 vs 期望值，逐环比对

第二阶段（`selinux_policy_classifier` / `avc_deny_classifier`）对第一阶段判出的"矛盾"记录，
**逐环对比"实际观测到的"和"本应是的"**，第一个对不上的环就是根因。顺序固定为
**客体标签 → 主体域 → 规则**（因为标签错会让规则查询失去意义，必须先排标签）。

观测值直接从事件的 context 抽（context 第 3 段就是 type）：

```text
S = type(scontext)     T = type(tcontext)     C = tclass     P = 越权/被拒的权限
```

期望值来自三张**参考表**（见 §7）：

```text
⓪ 先看 policy_result（甄别 permissive 假象）：
     allow 方向：policy_result == deny  → policy_correct
                 （策略其实拒绝，runtime 的 allow 只是 permissive 未强制执行）
     deny  方向：AVC 事件 denied==1 本身就是策略裁决；permissive 字段只说明是否强制执行

① expected_T = file_contexts.查(path)
     若 T ≠ expected_T            → TMM   （文件贴错标签）
② expected_S = expected_domains.查(comm)
     若 S ≠ expected_S            → TTLP  （进程没在正确的域）
③ 标签都对，看 allow_rules：
     allow 方向：存在授予 P 的规则 → PCI            （规则太宽，删）
     deny  方向：不存在授予 P 的规则 → missing_allow （规则缺，加）
                 规则却存在仍被拒   → undetermined   （boolean/MLS/约束，需人工）
```

每一类都直接产出**可执行修复命令**（relabel / type_transition / 删或加 allow）。

---

## 7. 三张参考表是怎么来的（provenance）

"期望值"必须有依据，依据就是被分析主机**当前的 SELinux 策略本身**。
`export_selinux_reference.py` 在主机上跑三条命令并解析：

| 表 | 来源命令 | 解析得到 |
| --- | --- | --- |
| `file_contexts`（`r_f`） | `semanage fcontext -l` | 路径正则 → 期望 type |
| `expected_domains`（`r_t` 化简） | `sesearch --type_trans` + file_contexts | process 转换的 exec type，经 file_contexts 反查字面路径，basename（截断 15 字符对齐内核 comm）→ 期望域 |
| `allow_rules`（`r_e`） | `sesearch --allow -c file` | (源域, 客体 type, 安全类) → 权限集合 |

例如 `semanage fcontext -l` 里有 `/var/www/private(/.*)? → httpd_private_content_t`，这就是
"private 目录下的文件**本应**是 private 标签"的依据；`sesearch --type_trans` 里有
`init_t httpd_exec_t:process httpd_t`，加上 `/usr/sbin/httpd → httpd_exec_t`，推出
"comm=httpd **本应**在 httpd_t 域"。

> 没有参考表时分类器会降级成启发式（通用 type 猜 TMM 等）并标 `confidence: low` —— 能给
> 方向但不保证准，所以参考表是高置信度的前提。导出方式详见
> [selinux_policy_classification_design.md §3.1](./selinux_policy_classification_design.md)。

---

## 8. 两条完整 trace（一正一反）

### 8.1 allow 方向：标签贴错导致越权放行（TMM）

```text
关联输入:
  policy: 允许 httpd 读 /var/www/html/，actions=[read]
  事件:   httpd 读 /var/www/private/secret
          runtime_result=allow, policy_result=inferred_allow
          scontext→httpd_t, tcontext→httpd_sys_content_t

第一阶段:
  /var/www/private/secret 不在 /var/www/html/ 下 → 资源越界
  runtime_result=allow → status = resource_out_of_scope   （越界行为确实发生了）

第二阶段（逐环比对）:
  ⓪ policy_result=inferred_allow（不是 deny）→ 策略确实放行了，不是 permissive 假象
     → 确认这是真正的 allow 方向异常【矛盾：用户禁、策略放】
  ① file_contexts.查(/var/www/private/secret) = httpd_private_content_t
     观测 T = httpd_sys_content_t  ≠  期望  → 命中 TMM
  根因: 这个 private 文件被错贴成了 html 的 sys_content 标签，
        所以 httpd_t 对它的 read 规则恰好命中，越权才"合法"放行。

结论: TMM / direction=allow / high
修复: semanage fcontext -a -t httpd_private_content_t '/var/www/private(/.*)?'
      && restorecon -v /var/www/private/secret
```

> 对照：如果同样的事件 `policy_result=deny`（permissive 模式下 `runtime_result` 仍是
> allow），第二阶段步骤 ⓪ 就会直接判 `policy_correct` —— 策略其实拒绝了，只是没强制执行，
> 不算策略错误。

注意：根因**不是 allow 规则** —— `allow httpd_t httpd_sys_content_t:file read` 本身没错，
错在文件不该穿这件"马甲"。这正是先查标签、后查规则的意义。

### 8.2 deny 方向：缺 allow 规则导致合法访问被拒（missing_allow）

```text
关联输入:
  policy: 允许 appd 写 /opt/app/data/，actions=[write]
  AVC:    appd 写，denied=1，scontext→appd_t, tcontext→appd_data_t, perm=write

第一阶段（意图检查）:
  被拒动作 write ∈ 用户 actions[write]  → 这是合法访问被拦     【矛盾：用户允、SELinux拒】

第二阶段（逐环比对）:
  ① file_contexts.查(/opt/app/data) = appd_data_t = 观测 T   → 标签对，跳过
  ② expected_domains.查(appd) = appd_t = 观测 S              → 域对，跳过
  ③ allow_rules 里 appd_t→appd_data_t:file 只有 [read open getattr]，无 write
     → 缺规则 → 命中 missing_allow

结论: missing_allow / direction=deny / high
修复: 新增 allow appd_t appd_data_t:file { write };（可用 audit2allow 辅助）
```

如果第 ③ 步发现规则其实存在却仍被拒，就落 `undetermined` —— 根因在三机制之外（boolean
关了、MLS 级别不够、约束/neverallow），系统不瞎猜，标低置信并提示人工排查。

---

## 9. 一句话总览

```text
内核态 LSM/AVC 事件 ──┐
                     ├─(关联)→ [意图, 实际] ─(一阶段:行为是否越界,看 runtime_result)→ 越界? ─是→ (二阶段:⓪看 policy_result 甄别 permissive → 观测vs期望逐环) → TMM/TTLP/PCI/missing_allow + 修复命令
用户态 IR policy ─────┘                                                              └─否→ normal                                              └ policy_result=deny → policy_correct
                                                                          期望值 ↑
主机策略 (semanage/sesearch) ─(export)→ file_contexts / expected_domains / allow_rules
```

- **发现策略有误** = 用户态意图与 SELinux 策略裁决（`policy_result`，**不是**
  `runtime_result`）出现矛盾。一阶段先用 `runtime_result` 判行为是否越界，二阶段步骤 ⓪ 再用
  `policy_result` 甄别 permissive 假象，确认是真正的策略矛盾。
- **定位是哪条策略** = 观测标签/域/规则与主机策略导出的期望值逐环比对，第一个不符的环即
  根因（二阶段）。
- **怎么改** = 每一类直接对应一条修复动作（relabel / 补转换 / 删或加 allow 规则）。

整条链路在 `detection/test/test_integration_pipeline.py` 里有从"原始策略文本 → 参考表 →
关联记录 → 归因结论"的端到端断言锁定。
