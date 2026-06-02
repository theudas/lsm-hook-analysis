---
marp: true
theme: default
paginate: true
size: 16:9
header: 'SELinux 策略异常检测'
footer: 'lsm-hook-analysis · 基于 SPRT 分类'
style: |
  section {
    font-size: 26px;
    line-height: 1.45;
  }
  section.lead h1 { font-size: 52px; }
  h1 { font-size: 36px; color: #1a4d8f; }
  h2 { font-size: 30px; color: #1a4d8f; }
  table { font-size: 21px; }
  pre, code { font-size: 19px; }
  .small { font-size: 20px; }
  .hl { color: #c0392b; font-weight: bold; }
  .ok { color: #27ae60; font-weight: bold; }
---

<!-- _class: lead -->

# SELinux 策略异常检测

## 从 LSM hook 数据到“哪条策略错了 + 怎么改”

基于运行时数据的确定性归因 · 对齐 SPRT 三分类

---

## 我们要解决什么问题

- SELinux 策略规则数以万计、语义复杂，**误配置是 80%+ 漏洞的根源**（SPRT）
- 误配置有两个方向：
  - **太松**：放过了不该允许的访问（提权风险）
  - **太紧**：拦了本该允许的访问（可用性问题）
- 目标：在运行时**自动检测出策略有误**，并**定位到具体哪类策略规则**，给出可执行修复

> 不同于 SPRT 用 NLP 分析 CVE 文本（有误分类率），我们有运行时 ground truth，
> 可以做**确定性、可解释**的归因。

---

## 整体架构：一图看全

```text
内核态 LSM/AVC 事件 ──┐
                     ├─(关联)→ [意图, 实际] ─→ ① 行为是否越界 ─→ ② 是哪条策略 ─→ 修复建议
用户态 IR policy ─────┘                         (file_anomaly_     (selinux_policy_
                                                 detector)          classifier /
                                                                    avc_deny_classifier)
                                                          期望值 ↑
主机策略 ─(semanage/sesearch 导出)→ file_contexts / expected_domains / allow_rules
```

- **第一阶段**：行为是否偏离用户意图（越界检测）
- **第二阶段**：偏离的根因是哪条 SELinux 策略规则（归因 + 修复）
- **参考知识库**：从主机策略导出的“期望值”，是高置信归因的依据

---

## 核心思想：两个权威，一个矛盾

判定“策略错了”**不靠某个访问看起来可疑**，而靠**两个独立权威对同一访问给出矛盾结论**：

| 权威 | 来源 | 表达 |
| --- | --- | --- |
| **用户态意图** | 归一化 IR policy | 本应允许的资源范围 + 操作 |
| **SELinux 策略裁决** | 内核事件 `policy_result` | 策略实际怎么判（allow/deny） |

```jsonc
// 用户态意图 (oracle)
{ "effect":"allow", "normalized_prefix":"/var/www/html/", "actions":["read"] }
```

**矛盾 = 策略有误。** 检测的全部工作就是可靠地制造并比对这个矛盾。

---

## 关键细节：runtime_result ≠ policy_result

内核事件的 `result` 里有两个**必须区分**的字段：

| 字段 | 含义 | 关键性质 |
| --- | --- | --- |
| `runtime_result` | 运行时**实际**结果 | <span class="hl">permissive 模式下恒为 allow</span>（访问不会真被拦） |
| `policy_result` | SELinux **策略本身**的裁决 | 不受 enforcing/permissive 影响 |

<br>

> ⚠️ **判断策略对不对必须看 `policy_result`**，不能看 `runtime_result`。
> 否则 permissive 下“策略其实 deny、只是没强制执行”会被误判成“策略放行了越权”。
>
> `runtime_result` 只回答“越界行为是否真的发生了”（行为层面）。

---

## 真值表：什么才算“策略有误”

比对 **用户态意图** × **`policy_result`**：

| 用户态意图 | `policy_result` | 结论 |
| --- | --- | --- |
| 不允许 | inferred_allow | <span class="hl">❌ 太松 → allow 方向异常</span> |
| 允许 | deny | <span class="hl">❌ 太紧 → deny 方向异常</span> |
| 不允许 | deny | <span class="ok">✅ 拦得对 → policy_correct</span> |
| 允许 | inferred_allow | <span class="ok">✅ 一致 → normal</span> |

只有**对角线两格（矛盾）**才是策略有误。

> 这张表在 enforcing / permissive 两种模式下都成立——因为它不依赖 `runtime_result`。

---

## 数据来源 ①：LSM hook 事件（allow 方向）

`lha_centos9_capture` 抓 hook（如 `selinux_file_open`）→ resolver 结构化 → 用户态

```jsonc
{
  "hook": "selinux_file_open",
  "subject": { "comm": "httpd", "scontext": "...:httpd_t:s0" },     // 主体域 S
  "request": { "perm": "open|read" },                              // 请求权限
  "target":  { "path": "/var/www/private/secret",
               "tclass": "file",
               "tcontext": "...:httpd_sys_content_t:s0" },          // 客体 type T
  "result":  { "runtime_result": "allow",                          // 行为
               "policy_result": "inferred_allow" }                 // 策略裁决
}
```

**主体标签 + 客体标签 + 权限 + 两种结果** 都在一条记录里——归因所需信息齐备。

---

## 数据来源 ②：AVC deny 事件（deny 方向）

`lha_centos9_avc_capture` 挂 `selinux_audited` tracepoint，**仅 `denied != 0` 触发**

```jsonc
{
  "scontext": "...:appd_t:s0",        // 主体域 S
  "tcontext": "...:default_t:s0",     // 客体 type T
  "tclass": "file", "perm": "open|read",
  "comm": "appd",
  "permissive": 0,                    // 是否被强制执行
  "denied": 1                         // 策略裁决 = deny
}
```

- `denied==1` **本身就是策略裁决**（deny），`permissive` 说明是否真的拦了
- <span class="hl">硬约束：AVC 事件没有 path</span> → 客体期望标签要从关联的 policy 借

---

## 关联：把“实际发生”和“本应允许”对齐

上游关联模块把每条内核事件配上它落入的用户态 policy：

```text
[ 用户态 IR policy , 内核态事件 ]
```

- allow 方向：配 **file 事件**
- deny 方向：配 **AVC 事件**

> 没有关联，就没有“意图 vs 实际”的对比对象——这是后续一切的前提。

---

## 第一阶段：行为是否偏离意图

`file_anomaly_detector`，回答两个纯粹的问题（**还不下“策略错”结论**）：

**(a) 资源范围**
```text
target.path startswith normalized_prefix ?
/var/www/private/secret  vs  /var/www/html/   → False → 越界
```

**(b) 权限覆盖**（内核 perm 归一化到用户动作）
```text
open→read  read→read  write→write  append→write  exec→execute  search→read
exec → execute ∉ [read] → 越权
```

---

## 第一阶段：状态判定（看 runtime_result）

| 状态 | 含义 | 行为是否实际越界 |
| --- | --- | --- |
| `normal` | 在范围内、权限被覆盖 | 否 |
| `permission_exceeded` | 权限越界 + `runtime=allow` | 是 |
| `resource_out_of_scope` | 资源越界 + `runtime=allow` | 是 |
| `blocked_violation_attempt` | 越界但 `runtime=deny` | 否（运行时被拦）|
| `runtime_error` / `invalid_input` / ... | 异常态 | — |

> 第一阶段用 `runtime_result` 判**行为**；策略对错留给第二阶段用 `policy_result` 判。

---

## 为什么“矛盾”就等于策略错

> 而不是“程序在作恶”

- 内核态事件是 SELinux **已按当前策略裁决完**的结果
- `policy_result=inferred_allow` = 在当前 **label + 规则** 下策略认为合法
- 既然内核正常、策略已执行，那么“用户禁止、策略却 allow”只可能是：
  1. **客体/主体 label 贴错了**，或
  2. **策略规则授权太宽**
- 反向（用户允许、策略 deny）同理：label 错 或 缺规则

<br>

→ 矛盾的根因**必然收敛到 SELinux 的三种策略机制**（SPRT 论文 3.3 节）

---

## 三种策略机制 = 三类根因（SPRT 形式化）

SELinux 裁决一次访问 `允许(S, T, C, P)?` 只用三种规则：

| 机制 | 形式化 | 决定 | 出错 |
| --- | --- | --- | --- |
| 文件-标签映射 `r_f` | `Type → File` | 客体贴什么 type (T) | 贴错 → **TMM** 标签不对 |
| 类型转换 `r_t` | `<t_s,t_r,c,t_d>` | 进程 exec 后进哪个域 (S) | 没转/转错 → **TTLP** 域转换错 |
| 类型强制 `r_e` | `<allow,d,t,c,{p}>` | 域对 type 有哪些权限 | 太宽→**PCI**；缺→**missing_allow** |

- **S** 由 `r_t` 决定，**T** 由 `r_f` 决定，能否通过由 `r_e` 决定
- 任何裁决错误，**必落在这三者之一**

---

## 第二阶段：逐环比对（观测 vs 期望）

观测值从 context 抽（第 3 段即 type）：`S=type(scontext)`、`T=type(tcontext)`、`C=tclass`

```text
⓪ 甄别 permissive 假象：
     allow 方向: policy_result==deny → policy_correct（策略其实拒绝，非错误）
     deny  方向: AVC denied==1 即策略裁决；permissive 仅说明是否强制执行

① T ≠ expected_T (file_contexts.查 path)        → TMM   （文件贴错标签）
② S ≠ expected_S (expected_domains.查 comm)      → TTLP  （进程域不对）
③ 标签都对，看 allow_rules：
     allow: 存在授予 P 的规则 → PCI            （太宽，删）
     deny : 无授予 P 的规则  → missing_allow   （缺，加）
            规则却存在仍被拒 → undetermined    （boolean/MLS/约束，人工）
```

> 顺序固定 **客体标签 → 主体域 → 规则**：标签错会让规则查询失去意义，必须先排标签。

---

## 期望值从哪来：三张参考表的 provenance

“期望值”依据 = 被分析主机**当前的 SELinux 策略本身**
（`export_selinux_reference.py` 导出）

| 表 | 来源命令 | 解析得到 |
| --- | --- | --- |
| `file_contexts` (`r_f`) | `semanage fcontext -l` | 路径正则 → 期望 type |
| `expected_domains` (`r_t`) | `sesearch --type_trans` + file_contexts | comm → 期望域 |
| `allow_rules` (`r_e`) | `sesearch --allow -c file` | (S, T, class) → 权限集合 |

```text
/var/www/private(/.*)? → httpd_private_content_t   ← “private 文件本应是 private 标签”
init_t httpd_exec_t:process httpd_t + /usr/sbin/httpd→httpd_exec_t
                                                   ← “comm=httpd 本应在 httpd_t 域”
```

> 无参考表时降级为启发式，标 `confidence: low`——能给方向但不保证准。

---

## Trace ①：allow 方向 · 标签贴错（TMM）

```text
输入: policy 允许 httpd 读 /var/www/html/ ([read])
      事件 httpd 读 /var/www/private/secret
           runtime=allow, policy_result=inferred_allow
           S=httpd_t, T=httpd_sys_content_t

一阶段: 路径越界 + runtime=allow → resource_out_of_scope（越界确实发生）

二阶段:
  ⓪ policy_result≠deny → 真的是策略放行（非 permissive 假象）
  ① file_contexts(/var/www/private/secret)=httpd_private_content_t
     观测 T=httpd_sys_content_t ≠ 期望 → 命中 TMM
```

<span class="hl">根因不是 allow 规则</span>：`allow httpd_t httpd_sys_content_t:file read` 没错，
错在文件穿错了“马甲”。

**修复**：`semanage fcontext -a -t httpd_private_content_t '/var/www/private(/.*)?' && restorecon`

---

## Trace ②：deny 方向 · 缺规则（missing_allow）

```text
输入: policy 允许 appd 写 /opt/app/data/ ([write])
      AVC  appd 写, denied=1, S=appd_t, T=appd_data_t, perm=write

一阶段(意图检查): write ∈ actions[write] → 合法访问被拦【矛盾：用户允、策略拒】

二阶段:
  ① file_contexts(/opt/app/data)=appd_data_t = 观测 T  → 标签对，跳过
  ② expected_domains(appd)=appd_t = 观测 S             → 域对，跳过
  ③ allow_rules 中 appd_t→appd_data_t:file 只有 [read open getattr]，无 write
     → 命中 missing_allow
```

**修复**：新增 `allow appd_t appd_data_t:file { write };`（可用 audit2allow 辅助）

---

## permissive 假象的甄别（步骤 ⓪ 的意义）

同一次越权访问，两种模式下数据不同：

| 模式 | `runtime_result` | `policy_result` | 一阶段 | 二阶段 ⓪ |
| --- | --- | --- | --- | --- |
| enforcing | deny | deny | blocked_violation_attempt | policy_correct |
| **permissive** | <span class="hl">allow</span> | deny | permission_exceeded | <span class="ok">policy_correct</span> |

<br>

> 若只看 `runtime_result`，permissive 行会被误判成“策略放行了越权”。
> 步骤 ⓪ 用 `policy_result==deny` 把它正确归为 `policy_correct`。

---

## 输出：可执行的修复建议

每条归因输出 `selinux_classification`：

```jsonc
{
  "category": "TMM | TTLP | PCI | missing_allow | undetermined | policy_correct | not_applicable",
  "direction": "allow | deny",
  "confidence": "high | low",
  "observed": { "S":"...", "T":"...", "C":"file", "P":["read"] },
  "expected": { "T":"httpd_private_content_t" },
  "evidence": ["object type '...' != expected '...'"],
  "recommended_fix": { "kind":"relabel|type_transition|add_allow|remove_allow",
                       "command":"semanage fcontext ... && restorecon ..." }
}
```

> 直接给运维“该调哪类策略 + 具体命令”，即 SPRT 所谓的 “rules to be modified”。

---

## 健壮性：分级与降级

- **置信度**
  - 有参考表 → 确定性判定，`high`
  - 无参考表 → 启发式（通用 type 猜 TMM；宽泛域猜 TTLP）→ `low`
- **不瞎猜**
  - 标签/域都对、规则也在，却仍被拒 → `undetermined`，提示查 boolean/MLS/约束
- **诚实标注边界**
  - `not_applicable`：无关联策略 / 非 file allow / 数据缺失
  - `policy_correct`：SELinux 拦得对，无需改

---

## 端到端 · 测试锁定

```text
主机策略文本 ─(build_reference)→ 三张参考表
                                     │
关联记录 [意图,实际] ─(detect)→ 越界? ─(classify ⓪→①②③)→ 归因 + 修复
```

- `detection/test/test_integration_pipeline.py`
  从 **原始策略文本 → 参考表 → 关联记录 → 归因结论** 全链路断言
- 覆盖两个方向、所有类别、permissive 甄别
- 全套 **61 个单元/集成测试通过**

---

<!-- _class: lead -->

# 总结

**发现策略有误** = 用户态意图 与 `policy_result` 矛盾（不看 `runtime_result`）

**定位哪条策略** = 观测标签/域/规则 与 主机导出的期望值逐环比对

**怎么改** = 每类直接对应 relabel / 补转换 / 删或加 allow 规则

<br>

<span class="small">对齐 SPRT 三分类（TMM/TTLP/PCI），扩展出 deny 方向（missing_allow），
确定性、可解释、可执行。</span>
