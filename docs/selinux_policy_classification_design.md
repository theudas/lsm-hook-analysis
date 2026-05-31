# SELinux 策略异常分类模块设计

本文档描述在 file 关联结果异常检测（见
[file_anomaly_detection_design.md](./file_anomaly_detection_design.md)）之后，如何把
检测出的“越权但被放行”异常进一步归因到具体的 SELinux 策略机制，方便运维知道该调整
哪一类策略。

实现见：

```text
detection/selinux_policy_classifier.py
detection/test/test_selinux_policy_classifier.py
```

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
都隐含 `runtime_result == allow`，即 SELinux 放行了越权访问）。其余情况：

- `blocked_violation_attempt`（内核已 deny）→ `policy_correct`，策略本身正确，无需调整；
- `normal` / `invalid_input` / `unsupported_policy` / `runtime_error` 及非法对象 →
  `not_applicable`。

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
- `semanage` / `sesearch` 输出到参考 JSON 的自动解析（当前由外部导出为 JSON 后传入）；
- file_contexts 的完整 SELinux specificity 排序（v1 用 pattern 长度近似）；
- AVC deny 方向（“该允许却被拒”）的归因。

这些可在后续输入字段更完整、或接入主机策略导出工具后扩展。
```
