# file 关联结果异常检测模块设计

本文档描述在已经完成关联的前提下，如何判断内核态实际文件操作是否与用户态允许操作一致。

输入来自关联模块输出的一条二元数组：

```json
[
  {
    "policy_ref": "policies[1]",
    "subject": "file",
    "effect": "allow",
    "resource_type": "file",
    "identifier": "/workspace/outputs/**",
    "normalized_prefix": "/workspace/outputs/",
    "actions": ["read", "write", "create"]
  },
  {
    "hook": "selinux_file_open",
    "hook_signature": "static int selinux_file_open(struct file *file)",
    "timestamp_ns": 1778482476753106527,
    "subject": {
      "pid": 14942,
      "tid": 14942,
      "scontext": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
      "comm": "tee"
    },
    "request": {
      "mask_raw": 0,
      "obj_type": "reg",
      "perm": "open|read"
    },
    "target": {
      "dev": "dm-0",
      "ino": 34803941,
      "type": "reg",
      "path": "/workspace/outputs/week_report.md",
      "tclass": "file",
      "tcontext": "system_u:object_r:user_home_t:s0"
    },
    "result": {
      "ret": 0,
      "runtime_result": "allow",
      "policy_result": "inferred_allow"
    }
  }
]
```

数组含义固定为：

- 第 1 个元素：用户态归一化 file policy
- 第 2 个元素：内核态原始 file 事件

## 1. 检测目标

异常检测模块回答两个问题：

```text
1. 内核态访问的 path 是否仍在用户态允许的 normalized_prefix 范围内。
2. 内核态 request.perm 表达的操作是否被用户态 actions 覆盖。
```

关联模块已经做过路径匹配，但异常检测模块仍建议复核一次路径范围，因为检测结论要独立可解释。

## 2. 输入字段使用

异常检测只使用输入数组中已经存在的字段。

用户态字段：

| 字段 | 用途 |
| --- | --- |
| 第 1 个元素.`policy_ref` | 定位命中的原始用户态策略 |
| 第 1 个元素.`effect` | 当前只处理 `allow` |
| 第 1 个元素.`resource_type` | 当前只处理 `file` |
| 第 1 个元素.`identifier` | 保留用户态原始资源表达 |
| 第 1 个元素.`normalized_prefix` | 判断资源范围 |
| 第 1 个元素.`actions` | 判断权限是否被允许 |

内核态字段：

| 字段 | 用途 |
| --- | --- |
| 第 2 个元素.`timestamp_ns` | 输出检测结果时回溯事件 |
| 第 2 个元素.`hook` | 区分事件来源 hook |
| 第 2 个元素.`subject.pid` | 回溯进程 |
| 第 2 个元素.`subject.tid` | 回溯线程 |
| 第 2 个元素.`subject.comm` | 回溯进程名 |
| 第 2 个元素.`request.perm` | 判断内核态实际请求权限 |
| 第 2 个元素.`target.path` | 判断资源范围 |
| 第 2 个元素.`target.type` | 辅助判断目标类型 |
| 第 2 个元素.`target.tclass` | 辅助判断目标安全类 |
| 第 2 个元素.`result.runtime_result` | 判断这次操作实际是否被内核运行时允许 |
| 第 2 个元素.`result.policy_result` | 保留内核侧策略推断结果 |

## 3. 检测步骤

### 3.1 基础结构校验

输入必须是长度为 2 的数组。

第 1 个元素必须至少包含：

```text
normalized_prefix
actions
effect
resource_type
```

第 2 个元素必须至少包含：

```text
request.perm
target.path
result.runtime_result
```

如果缺少这些字段，检测模块输出数据质量异常。

### 3.2 策略类型校验

当前只处理：

```text
第 1 个元素.resource_type == "file"
第 1 个元素.effect == "allow"
```

如果不是 file allow 策略，检测模块可以标记为不支持检测。

### 3.3 资源范围检测

判断：

```text
第 2 个元素.target.path startswith 第 1 个元素.normalized_prefix
```

如果成立，资源范围一致。

如果不成立，说明内核态实际访问路径不在用户态允许范围内，应判定为资源范围异常。

虽然关联模块通常只输出已经匹配的记录，但这里仍然保留该检查，避免上游关联错误或后续输入格式变化。

### 3.4 权限归一化

内核态 `request.perm` 是字符串，可能是：

```text
read
open|read
write
append
search
exec
```

检测模块先按 `|` 拆分为权限 token。

然后把内核态权限 token 映射到用户态动作名。v1 建议：

| 内核态权限 | 用户态 action |
| --- | --- |
| `open` | `read` |
| `read` | `read` |
| `write` | `write` |
| `append` | `write` |
| `exec` | `execute` |
| `search` | `read` |

说明：

- `open` 先按 `read` 处理，因为当前没有更细的打开模式字段。
- `append` 归入 `write`。
- `search` 常见于目录搜索，v1 先归入 `read`，后续可单独引入 `search` action。
- `create` 通常不是内核态当前 `request.perm` 直接输出的 token。创建行为在 hook 层可能表现为目录写权限或后续文件写权限，v1 先不从 `write` 反推 `create`。

### 3.5 权限一致性检测

将归一化后的内核态动作集合记为：

```text
kernel_actions
```

将用户态允许动作集合记为：

```text
allowed_actions = 第 1 个元素.actions
```

判断：

```text
kernel_actions 是否全部包含在 allowed_actions 中
```

如果全部包含，权限一致。

如果存在任意一个动作不在 `actions` 中，判定为权限异常。

示例：

```text
request.perm = open|read
kernel_actions = [read]
actions = [read, write, create]
结果 = 权限一致
```

示例：

```text
request.perm = exec
kernel_actions = [execute]
actions = [read, write, create]
结果 = 权限异常
```

### 3.6 运行时结果处理

`result.runtime_result` 表示内核最终运行时结果：

```text
allow
deny
error
```

建议检测模块只把 `runtime_result == "allow"` 的越权行为标记为高优先级异常。

如果 `runtime_result == "deny"`，说明内核已经拒绝该操作。即使它超出用户态权限，也可以标记为被拦截的异常尝试。

如果 `runtime_result == "error"`，优先标记为运行时错误或待审计。

## 4. 检测结论

异常检测模块可以输出自己的结果字段。下面字段是检测模块新生成的结论，不是用户态或内核态原始输入字段。

建议结论类型：

| 结论 | 含义 |
| --- | --- |
| `normal` | 资源范围一致，权限一致 |
| `resource_out_of_scope` | 内核态 `target.path` 不在用户态 `normalized_prefix` 下 |
| `permission_exceeded` | 内核态权限归一化后不被用户态 `actions` 覆盖 |
| `blocked_violation_attempt` | 存在越界或越权，但 `runtime_result` 为 `deny` |
| `unsupported_policy` | 当前不是 file allow 策略 |
| `invalid_input` | 输入结构或必要字段缺失 |
| `runtime_error` | 内核态 `runtime_result` 为 `error` |

优先级建议：

```text
invalid_input
unsupported_policy
runtime_error
resource_out_of_scope
permission_exceeded
blocked_violation_attempt
normal
```

当同一条记录同时出现资源范围异常和权限异常时，建议同时保留两个原因。

## 5. 输出格式

检测模块可以输出 NDJSON：

```text
file_anomaly_events.ndjson
```

一行对应一条关联输入。

为了保留可追溯性，建议输出：

- 原始关联输入数组
- 检测模块生成的结论
- 检测模块生成的原因

示例：

```json
{
  "input": [
    {
      "policy_ref": "policies[1]",
      "subject": "file",
      "effect": "allow",
      "resource_type": "file",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read", "write", "create"]
    },
    {
      "hook": "selinux_file_open",
      "hook_signature": "static int selinux_file_open(struct file *file)",
      "timestamp_ns": 1778482476753106527,
      "subject": {
        "pid": 14942,
        "tid": 14942,
        "scontext": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "comm": "tee"
      },
      "request": {
        "mask_raw": 0,
        "obj_type": "reg",
        "perm": "open|read"
      },
      "target": {
        "dev": "dm-0",
        "ino": 34803941,
        "type": "reg",
        "path": "/workspace/outputs/week_report.md",
        "tclass": "file",
        "tcontext": "system_u:object_r:user_home_t:s0"
      },
      "result": {
        "ret": 0,
        "runtime_result": "allow",
        "policy_result": "inferred_allow"
      }
    }
  ],
  "detection": {
    "status": "normal",
    "reasons": [],
    "kernel_actions": ["read"],
    "allowed_actions": ["read", "write", "create"],
    "path_in_scope": true
  }
}
```

对于权限异常：

```json
{
  "input": [
    {
      "policy_ref": "policies[1]",
      "subject": "file",
      "effect": "allow",
      "resource_type": "file",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read", "write", "create"]
    },
    {
      "hook": "selinux_file_permission",
      "hook_signature": "static int selinux_file_permission(struct file *file, int mask)",
      "timestamp_ns": 1778482476753106527,
      "subject": {
        "pid": 14942,
        "tid": 14942,
        "scontext": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "comm": "tee"
      },
      "request": {
        "mask_raw": 0,
        "obj_type": "reg",
        "perm": "exec"
      },
      "target": {
        "dev": "dm-0",
        "ino": 34803941,
        "type": "reg",
        "path": "/workspace/outputs/week_report.md",
        "tclass": "file",
        "tcontext": "system_u:object_r:user_home_t:s0"
      },
      "result": {
        "ret": 0,
        "runtime_result": "allow",
        "policy_result": "inferred_allow"
      }
    }
  ],
  "detection": {
    "status": "permission_exceeded",
    "reasons": ["execute not in actions"],
    "kernel_actions": ["execute"],
    "allowed_actions": ["read", "write", "create"],
    "path_in_scope": true
  }
}
```

## 6. 对当前样例的检测结果

当前样例中：

```text
用户态 normalized_prefix = /workspace/outputs/
内核态 target.path       = /workspace/outputs/week_report.md
内核态 request.perm      = open|read
用户态 actions           = read, write, create
runtime_result           = allow
```

检测过程：

```text
target.path 在 normalized_prefix 范围内
open|read 归一化为 read
read 包含在 actions 中
runtime_result 为 allow
```

因此结论为：

```text
normal
```

## 7. 当前边界

当前 v1 不处理：

- 未关联上的内核态事件
- tool 类型策略
- pid/tid/query/task 级归因
- create 的精确内核语义
- SELinux `policy_result` 与用户态策略的深度一致性判断

这些可以在后续输入字段更完整后再扩展。
