# SELinux 策略异常分类模块设计

本文档描述在 file 关联结果异常检测（见
[file_anomaly_detection_design.md](./file_anomaly_detection_design.md)）之后，如何把
检测出的“越权但被放行”异常进一步归因到具体的 SELinux 策略机制，方便运维知道该调整
哪一类策略。

实现见：

```text
detection/selinux_policy_classifier.py
detection/test/test_selinux_policy_classifier.py
detection/export_selinux_reference.py
detection/test/test_export_selinux_reference.py
detection/avc_deny_classifier.py
detection/test/test_avc_deny_classifier.py
```

本模块分两个方向：

- **allow 方向**（§1–§9）：SELinux 放过了用户态不允许的访问（提权风险），由
  `selinux_policy_classifier` 处理。
- **deny 方向**（§10）：SELinux 拒绝了用户态本应允许的访问（可用性问题），由
  `avc_deny_classifier` 处理。

两个方向共用同一套形式化对应、参考知识库和决策树，只是触发条件相反、修复方向相反。

## 1. 背景与目标

第一阶段（`file_anomaly_detector`）回答的是 **“SELinux 是否放过了用户态策略不允许的
访问”**：当一条记录被判为 `permission_exceeded` 或 `resource_out_of_scope` 且
`runtime_result == allow` 时，说明 SELinux 在运行时放行了一次本不该被允许的访问。

第二阶段（本模块）回答的是 **“是哪一种 SELinux 策略机制放过了它”**，从而把异常映射成
可执行的策略调整建议。

分类标准参考 SPRT（*SPRT: Automatically Adjusting SELinux Policy for Vulnerability
Mitigation*, SACMAT 2024）提出的三类误配置漏洞。

## 2. 与 SPRT 的对齐

SPRT 把 SELinux 误配置漏洞分为三类，每一类精确对应一种 SELinux 策略规则（论文 3.2 节
给出了形式化定义）：

| SPRT 类别 | 中文 | 对应策略规则 | 形式化 | 根因 |
| --- | --- | --- | --- | --- |
| **TMM** (Type Missing/Mis-set) | 标签不对 | 文件-标签映射 | `r_f = Type → File` | 客体（文件/目录/进程）被打了错误的 type，或继承/定义错误 |
| **TTLP** (Transition Leads to Lax Privileges) | 域转换规则错误 | 类型转换规则 | `r_t = <t_s, t_r, c, t_d>` | 进程本应转换到受限域却没转换，保留了父进程（往往过宽）的域 |
| **PCI** (Policy Configured Improperly) | allow 规则错误 | 类型强制规则 | `r_e = <a, d, t, c, {p}>` | 标签都对，但存在一条过于宽松的 allow 规则 |

### 2.1 与 SPRT 方法的关键差异

SPRT 用 NLP 原型网络对 **CVE 描述文本** 做分类，因为它没有运行时 ground truth，只能
从文本特征推断类别，存在误分类率（论文报告约 92.84% 准确率）。

本模块的场景不同：我们拥有

1. 运行时真实的 LSM 事件（`subject.scontext` / `target.tcontext` / `tclass` / `path` /
   `request.perm` / `runtime_result`）；
2. 一个用户态 oracle（`normalized_prefix` + `actions`），它定义了“本应被允许的范围”。

因此本模块 **不需要 NLP**，而是基于“实际观测到的标签/规则”与“主机策略中本应是什么”
做对比，得到 **确定性、可解释** 的归因。SPRT 的 NLP 是这套方法在缺乏运行时数据时的退化
形态；本模块在缺少参考知识库时也提供启发式降级（见 §6）。

## 3. 参考知识库（三张表）

确定性归因需要“本应是什么”的依据，来自主机当前的 SELinux 策略，正好对应 SPRT 5.1 节抽
取的三类规则。知识库是一个可选的 JSON 对象，包含三张表（均可缺省）：

```json
{
  "file_contexts": [
    {"pattern": "/var/www/private(/.*)?", "type": "httpd_private_content_t"},
    {"pattern": "/var/www/html(/.*)?",    "type": "httpd_sys_content_t"}
  ],
  "expected_domains": {
    "httpd": "httpd_t"
  },
  "allow_rules": [
    {"source": "httpd_t", "target": "httpd_sys_content_t", "class": "file", "perms": ["read", "open"]}
  ]
}
```

| 表 | 对应 SPRT 规则 | 含义 | CentOS Stream 9 导出方式 |
| --- | --- | --- | --- |
| `file_contexts` | `r_f` | 路径正则 → 期望 type | `semanage fcontext -l`；单点核对用 `matchpathcon <path>` |
| `expected_domains` | `r_t`（化简版） | 进程名 → 应运行的受限域 | `sesearch --type_trans` 推导，或人工整理 |
| `allow_rules` | `r_e` | (源域, 客体type, 安全类) → 授予权限 | `sesearch --allow -s <S> -t <T> -c <C>` |

说明：

- `file_contexts` 的 `pattern` 是 SELinux file-context 风格的正则，按整串 `re.fullmatch`
  匹配路径。多个命中时 v1 取 **pattern 字符串最长** 的作为更具体的匹配（SELinux 真实排序
  更复杂，v1 用长度近似；后续可替换为更精确的 specificity 排序）。
- `expected_domains` 是 `r_t` 的化简：完整的类型转换需要 `<父域, exec type, class>`，而
  运行时事件里没有 exec type，因此 v1 用“进程名 → 期望域”近似。
- 缺省任意一张表都不会报错，只会让对应判定步骤跳过，并在无任何表时整体降级为启发式。

知识库通过 `--reference <file.json>` 传入，或 `load_reference()` 读取。

### 3.1 用导出脚本生成参考表

`detection/export_selinux_reference.py` 是一个 **主机侧** helper，在被分析的 CentOS
Stream 9 机器上运行，调用 `semanage` / `sesearch` 自动生成上述参考 JSON：

```bash
# 在目标主机上（需 root，需安装 policycoreutils-python-utils 与 setools-console）
python3 -m detection.export_selinux_reference -o selinux_reference.json

# 只导出关心的安全类的 allow 规则（默认 file,dir,lnk_file），减小体积
python3 -m detection.export_selinux_reference --classes file,dir -o selinux_reference.json

# 跳过 allow 规则导出（PCI 证据将缺少具体规则行，但 file_contexts/expected_domains 仍生成）
python3 -m detection.export_selinux_reference --no-allow -o selinux_reference.json
```

三张表的来源命令与解析要点：

| 表 | 来源命令 | 解析要点 |
| --- | --- | --- |
| `file_contexts` | `semanage fcontext -l` | 数据行是 3 列（2+ 空格分隔）；跳过表头、等价行、`<<none>>` |
| `expected_domains` | `sesearch --type_trans` + `file_contexts` | 取 `process` 类转换的 exec type，经 file_contexts 反查 **字面路径**，basename（截断到 15 字符，与内核 comm 对齐）作为 comm |
| `allow_rules` | `sesearch --allow -c <classes>` | 兼容花括号多权限与单权限两种形式 |

`expected_domains` 的推导是 `r_t` 的化简近似，存在两点已知约束（脆弱的解析逻辑已抽成纯
函数并单测覆盖，见 `test_export_selinux_reference.py`）：

- 只接受 **字面路径** 的 exec type（含正则元字符的 pattern 无法稳定得到 comm，直接跳过）；
- 同名 comm 指向不同域时整体丢弃，避免给出错误的高置信度结论。

生成脚本与分类器之间是松耦合：脚本只产出 JSON，分类器只消费 JSON，两边都不依赖对方的内部
实现，主机侧导出与离线分析可以分离。


## 4. 输入与输出

### 4.1 输入

本模块消费 **第一阶段的输出对象**：

```json
{
  "input": [ <归一化用户态 file policy>, <内核态原始 file 事件> ],
  "detection": { "status": "...", "kernel_actions": [...], "allowed_actions": [...], "...": "..." }
}
```

主体/客体标签从 `input[1]`（内核态事件）中读取：

| 字段 | 用途 |
| --- | --- |
| `input[1].subject.scontext` | 抽取主体域 `S`（context 第 3 段） |
| `input[1].subject.comm` | 查 `expected_domains` |
| `input[1].target.tcontext` | 抽取客体 type `T`（context 第 3 段） |
| `input[1].target.tclass` | 安全类 `C` |
| `input[1].target.path` | 查 `file_contexts` |
| `detection.status` | 决定是否进入归因 |
| `detection.kernel_actions` / `allowed_actions` | 计算越权权限 `P` |

> 说明：本模块的标签数据来自 file 事件通道（`selinux_file_open` 等），那里
> `scontext`/`tcontext` 都齐全。AVC deny 捕获通道（`lha_centos9_avc_capture.c`，仅在
> `denied != 0` 时触发）是“用户态认为该允许却被拒”这一相反方向的输入来源，不在 v1 主线
> 范围内。

### 4.2 输出

在输入对象上追加 `selinux_classification` 字段：

```json
{
  "input": [ ... ],
  "detection": { ... },
  "selinux_classification": {
    "category": "TMM | TTLP | PCI | policy_correct | not_applicable",
    "confidence": "high | low",
    "observed": {"S": "...", "T": "...", "C": "file", "P": ["execute"], "path": "...", "comm": "..."},
    "expected": {"T": "httpd_private_content_t"},
    "evidence": ["object type 'user_home_t' != expected 'httpd_private_content_t' for path ..."],
    "recommended_fix": {"kind": "relabel", "target_type": "...", "command": "semanage fcontext ... && restorecon ..."}
  }
}
```

- `confidence`：用参考表得出的为 `high`，启发式降级得出的为 `low`。
- `observed`：本次越权事件抽取出的 `S/T/C/P/path/comm`。
- `expected`：参考表给出的期望值（按类别给 `T` 或 `S`）。
- `evidence`：判定依据，便于人工复核。
- `recommended_fix`：可执行的修复建议，含 `kind` 与 `command`（模板里用占位符标出需人工补全
  的部分，如父域、exec type）。

## 5. 判定决策树

仅对 `detection.status ∈ {permission_exceeded, resource_out_of_scope}` 的记录归因（这些
都隐含 `runtime_result == allow`，即越权行为在运行时确实发生了）。其余情况：

- `blocked_violation_attempt`（运行时已 deny）→ `policy_correct`，策略本身正确，无需调整；
- `normal` / `invalid_input` / `unsupported_policy` / `runtime_error` 及非法对象 →
  `not_applicable`。

**步骤 ⓪（甄别 permissive 假象）**：`runtime_result` 在 permissive 模式下恒为 `allow`，并不
代表策略真的放行。因此归因前先看 `result.policy_result`——若为 `deny`，说明策略其实拒绝了
这次访问（只是 permissive 未强制执行），直接判 `policy_correct`，不进入下面的归因。只有
`policy_result` 为 `inferred_allow`（或 `unknown`）时才继续，此时才是策略真正放行了越权。

对需要归因的记录，按“哪一环偏离期望”分类，**顺序固定为 客体标签 → 主体域 → 规则**：

```text
S = type(subject.scontext)       # 主体域
T = type(target.tcontext)        # 客体 type
C = target.tclass
P = kernel_actions - allowed_actions   # 越权权限（路径越界时退化为全部 kernel_actions）
path = target.path

① expected_T = file_contexts.lookup(path)
   若 expected_T 存在 且 T != expected_T   →  TMM（标签不对）
      文件被打错标签，访问“借着错标签”溜过去；allow 规则本身可能没问题
      修复：semanage fcontext -a -t <expected_T> '<pattern>' && restorecon -v <path>

② expected_S = expected_domains.lookup(comm)
   若 expected_S 存在 且 S != expected_S   →  TTLP（域转换错）
      进程没转换到受限域（停在父域 / unconfined）
      修复：type_transition <parent_t> <exec_t>:process <expected_S>; 后重建策略

③ 标签都对（或前两步无偏离） →  PCI（allow 规则越权）
      存在 r_e = allow S T:C {…P…}，规则过宽
      修复：sesearch 定位该规则后，从中删除权限 P 并重建策略
```

要点：**TMM 看客体标签，TTLP 看主体域，PCI 看规则**，三者互斥且覆盖 SPRT 所述绝大多数误
配置提权。顺序不能调换——若客体标签本身就错，针对错 type 去查 allow 规则会得到误导性结论，
所以先排除标签问题。

## 6. 无参考表时的启发式降级

当未提供任何参考表时，分类器退化为启发式，并标记 `confidence = low`：

1. 客体 type 属于通用/共享类型集合（如 `default_t` / `user_home_t` / `tmp_t` /
   `var_t` 等）→ 猜测 **TMM**（疑似 mislabel）；
2. 否则主体域属于宽泛域集合（如 `unconfined_t` / `init_t` / `initrc_t` / `sysadm_t`
   等）→ 猜测 **TTLP**（疑似缺类型转换）；
3. 否则（标签看起来都比较具体）→ 猜测 **PCI**（疑似过宽 allow 规则）。

启发式顺序与确定性路径一致（客体优先），结果仅供参考，应尽快补齐参考知识库以获得 `high`
置信度。

## 7. 走查示例

以论文 4.2.2 的 httpd 场景为例：

```text
oracle：进程只应读 /var/www/html（httpd_sys_content_t）
观测：comm=httpd 读了 /var/www/private/secret，runtime=allow，越界
      target.tcontext type = httpd_sys_content_t
      subject.scontext type = httpd_t
判定：file_contexts.lookup(/var/www/private/secret) 期望 = httpd_private_content_t
      实际 T = httpd_sys_content_t ≠ 期望  →  TMM
修复：该目录标签错了（本该是 private 却继承了 sys_content），relabel 即可，
      不用动 allow 规则
```

若该目录标签其实是对的（确为 `httpd_private_content_t`）却仍被读到：①不命中、②主体域
也对，落到 ③ PCI——说明存在多余的 `allow httpd_t httpd_private_content_t:file read;`，
应删除。

## 8. 命令行用法

```bash
# 有参考知识库（确定性归因）
python3 -m detection.selinux_policy_classifier \
    file_anomaly_events.ndjson \
    -r selinux_reference.json \
    -o selinux_classification_events.ndjson

# 无参考知识库（启发式降级）
python3 -m detection.selinux_policy_classifier file_anomaly_events.ndjson
```

输入是第一阶段 `file_anomaly_detector` 的 NDJSON 输出，输出在每行追加
`selinux_classification`。

## 9. 当前边界

v1 暂不处理：

- 完整的 `r_t` 解析（需要 exec type 与父域，当前用进程名近似）；
- file 之外的安全类（`dir`/`process` 等）的精细化修复建议；
- file_contexts 的完整 SELinux specificity 排序（v1 用 pattern 长度近似）。

> 参考表的导出已由 `export_selinux_reference.py` 实现（见 §3.1）。
> AVC deny 方向（“该允许却被拒”）的归因已由 `avc_deny_classifier.py` 实现（见 §10）。

## 10. AVC deny 方向归因

allow 方向回答“SELinux 放过了不该放的访问”；deny 方向回答相反的问题：**SELinux 拒绝了
用户态本应允许的访问**——这是可用性问题而非提权问题。由 `avc_deny_classifier` 处理。

### 10.1 输入与数据约束

deny 方向的数据来自 AVC deny 捕获通道（`lha_centos9_avc_capture.c`，仅在
`sad->denied != 0` 时触发），用户态形态对应 `struct lha_avc_event_v1`：

```json
{
  "scontext": "system_u:system_r:httpd_t:s0",
  "tcontext": "system_u:object_r:default_t:s0",
  "tclass": "file",
  "perm": "open|read",
  "comm": "httpd",
  "permissive": 0,
  "denied": 1
}
```

关键约束：**AVC deny 事件没有 path**，只有 `scontext`/`tcontext`/`tclass`/`perm`/
`comm`。因此“被拒资源本应是什么 type”要靠 **关联到的用户态 policy** 提供：用
policy 的 `normalized_prefix`（或去掉通配后的 `identifier`）反查 `file_contexts` 得到期望
type。这比 allow 方向（有具体 path）要粗一些。

输入是关联记录 `[user_file_policy, avc_event]`，`policy` 可为 `null`（未关联）。

### 10.2 触发条件（与 allow 方向相反）

只有 **落在用户态意图之内** 的 deny 才是异常：

- `policy` 缺失 / 非 file allow 策略 → `not_applicable`（无法判断意图）；
- 被拒动作（`perm` 归一化后）∩ `policy.actions` 为空 → `policy_correct`（用户本就没打算
  允许，SELinux 拒得对）；
- 被拒动作 ∩ `policy.actions` 非空 → 合法操作被误拒，进入归因。

`permissive == 1` 时，该 deny 被审计但未强制执行（访问实际放行了）。仍照常归因，但在
`evidence` 中给出“这预示 enforcing 模式下会失败”的预警。

### 10.3 决策树与修复方向

复用同一棵树（客体标签 → 主体域 → 规则），但修复方向相反：

```text
① T != 期望 type（file_contexts.lookup(prefix)）  →  TMM
     客体标签错，导致合法访问被拒
     修复：relabel 到期望 type（restorecon）

② S != 期望域（expected_domains.lookup(comm)）     →  TTLP
     进程在错误域里，缺少应有权限
     修复：补/改 type_transition

③ 标签都对，但 allow_rules 里没有授予该权限的规则  →  missing_allow
     修复：新增 allow S T:C {P};（可借 audit2allow）

   标签都对，且 allow 规则存在却仍被拒          →  undetermined
     根因在三机制之外（boolean / MLS / 约束 / neverallow / 类型边界），
     低置信度，不给确定修复，提示人工排查
```

deny 方向特有的两个类别：

| 类别 | 含义 | 修复方向 |
| --- | --- | --- |
| `missing_allow` | 标签都对但缺 allow 规则 | **新增** allow 规则（对应 allow 方向 PCI 的反面） |
| `undetermined` | 有 allow 规则却仍被拒 | 三机制无法解释，排查 boolean/MLS/约束 |

无参考表时降级为启发式（`confidence = low`）：客体 type 为通用类型 → 猜 TMM；否则猜
`missing_allow`。deny 方向 **不做 TTLP 启发式**——被拒的往往正是受限域，且没有参考表时无法
判断进程“本应”在哪个域。

### 10.4 输出

与 allow 方向同构，`selinux_classification` 带 `direction: "deny"`：

```json
{
  "category": "TMM | TTLP | missing_allow | undetermined | policy_correct | not_applicable",
  "direction": "deny",
  "confidence": "high | low",
  "observed": {"S": "...", "T": "...", "C": "file", "P": ["read"], "comm": "...", "permissive": false},
  "expected": {"T": "httpd_private_content_t"},
  "evidence": ["..."],
  "recommended_fix": {"kind": "relabel | type_transition | add_allow", "command": "..."}
}
```

allow 方向的输出同样带 `direction: "allow"`，便于把两条流合并后按方向区分。

### 10.5 命令行用法

```bash
python3 -m detection.avc_deny_classifier avc_deny_records.ndjson \
    -r selinux_reference.json \
    -o avc_deny_classification_events.ndjson
```

输入是 `[policy, avc_event]` 的 NDJSON，输出在每行追加 `selinux_classification`。
