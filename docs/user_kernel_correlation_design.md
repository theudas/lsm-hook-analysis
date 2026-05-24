# 用户态 file 策略与内核态 file 事件关联模块设计

本文档只描述当前已经能拿到的字段如何做关联。原则是：

```text
关联模块不创造新的字段名，只把用户态已归一化 file policy 与内核态原始日志事件配对输出。
```

当前不考虑异常检测模块，因此本文档不判断：

- 内核实际操作是否越权
- 内核访问路径是否越界
- 内核权限是否被用户态 `actions` 覆盖
- 这条事件是否正常、异常或高风险

关联模块当前只做一件事：

```text
用用户态 normalized_prefix 匹配内核态 target.path。
匹配上，就输出这条用户态策略和这条内核态事件。
匹配不上，就不输出关联记录。
```

## 1. 用户态可提供字段

用户态原始策略中当前重点关注 file 类型：

```json
{
  "subject": "file",
  "object": {
    "type": "file",
    "identifier": "/workspace/outputs/**"
  },
  "action": ["read", "write", "create"],
  "effect": "allow"
}
```

关联模块使用用户态归一化后的 file policy：

```json
{
  "policy_ref": "policies[1]",
  "subject": "file",
  "effect": "allow",
  "resource_type": "file",
  "identifier": "/workspace/outputs/**",
  "normalized_prefix": "/workspace/outputs/",
  "actions": ["read", "write", "create"]
}
```

这些字段全部来自用户态归一化结果：

| 字段 | 用途 |
| --- | --- |
| `policy_ref` | 回溯原始 JSON 位置 |
| `subject` | 用户态资源/场景标签，当前 file 策略为 `file` |
| `effect` | 用户态策略效果，例如 `allow` |
| `resource_type` | 用户态资源类型，当前为 `file` |
| `identifier` | 用户态原始资源表达，例如 `/workspace/outputs/**` |
| `normalized_prefix` | 用于和内核态 `target.path` 做前缀匹配 |
| `actions` | 用户态允许权限集合，当前只透传，不做判断 |

`tool` 类型策略当前不参与 file 事件关联，因为你当前没有提供 `tool -> kernel file path/process/label` 的映射。

## 2. 内核态要取的字段

内核态日志示例中已经包含以下结构：

```json
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
    "path": "/etc/hosts",
    "tclass": "file",
    "tcontext": "system_u:object_r:net_conf_t:s0"
  },
  "result": {
    "ret": 0,
    "runtime_result": "allow",
    "policy_result": "inferred_allow"
  }
}
```

关联模块需要内核态取这些字段，字段名保持内核日志原样：

| 字段 | 是否用于匹配 | 说明 |
| --- | --- | --- |
| `hook` | 否 | 保留事件来源 hook |
| `hook_signature` | 否 | 保留 hook 函数签名 |
| `timestamp_ns` | 否 | 保留事件时间戳 |
| `subject.pid` | 否 | 保留进程 pid |
| `subject.tid` | 否 | 保留线程 tid |
| `subject.scontext` | 否 | 保留主体 SELinux context |
| `subject.comm` | 否 | 保留进程名 |
| `request.mask_raw` | 否 | 保留原始 mask |
| `request.obj_type` | 否 | 保留请求对象类型 |
| `request.perm` | 否 | 保留内核解析权限，后续异常检测模块使用 |
| `target.dev` | 否 | 保留设备标识 |
| `target.ino` | 否 | 保留 inode 号 |
| `target.type` | 辅助 | 辅助确认目标是文件系统对象 |
| `target.path` | 是 | 与用户态 `normalized_prefix` 做路径前缀匹配 |
| `target.tclass` | 辅助 | 辅助确认目标安全类是 file/dir 等文件系统对象 |
| `target.tcontext` | 否 | 保留目标 SELinux context |
| `result.ret` | 否 | 保留原始 hook 返回值 |
| `result.runtime_result` | 否 | 保留运行时结果 |
| `result.policy_result` | 否 | 保留内核侧策略推断结果 |

当前真正用于关联匹配的核心字段只有：

```text
用户态: normalized_prefix
内核态: target.path
```

`target.type` 和 `target.tclass` 只用于确认这是 file 相关事件。`request.perm`、`result.runtime_result`、`result.policy_result` 都只透传给后续异常检测模块。

## 3. 关联规则

### 3.1 file 策略过滤

用户态只取：

```text
resource_type == "file"
```

或者从原始 JSON 里等价地取：

```text
subject == "file"
object.type == "file"
```

### 3.2 内核 file 事件过滤

内核态事件只处理 file 相关对象。可使用现有字段做辅助判断：

```text
target.tclass in ["file", "dir", "lnk_file", "chr_file", "blk_file", "fifo_file", "sock_file"]
或
target.type in ["reg", "dir", "lnk", "chr", "blk", "fifo", "sock"]
```

### 3.3 路径前缀匹配

核心匹配逻辑：

```text
内核态日志中的 target.path startswith 用户态归一化策略中的 normalized_prefix
```

示例：

```text
用户态 normalized_prefix = /workspace/outputs/
内核态 target.path       = /workspace/outputs/week_report.md
结果                    = 匹配
```

再比如：

```text
用户态 normalized_prefix = /workspace/outputs/
内核态 target.path       = /etc/hosts
结果                    = 不匹配
```

### 3.4 多条策略同时命中

如果多条用户态 file policy 都匹配同一条内核事件，当前不新增额外字段表达“被选中的策略”或“候选策略列表”。

最简单的输出方式是：

```text
每命中一条用户态 file policy，就输出一条 [用户态 file policy, 内核态事件] 配对记录。
```

这样输出字段仍然只来自用户态归一化结果和内核态原始日志。

## 4. 关联输出

关联模块输出建议仍然采用 NDJSON，一行一条关联记录：

```text
correlated_file_events.ndjson
```

每条记录是一个二元数组：

- 第 1 个元素：命中的用户态归一化 file policy
- 第 2 个元素：命中的内核态日志事件

这样不会新增任何字段名。数组内部的字段全部来自当前已经能提供的数据。

### 4.1 命中示例

用户态策略：

```json
{
  "policy_ref": "policies[1]",
  "subject": "file",
  "effect": "allow",
  "resource_type": "file",
  "identifier": "/workspace/outputs/**",
  "normalized_prefix": "/workspace/outputs/",
  "actions": ["read", "write", "create"]
}
```

内核态事件：

```json
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
```

关联输出：

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

### 4.2 未命中示例

用户态策略：

```json
{
  "policy_ref": "policies[1]",
  "subject": "file",
  "effect": "allow",
  "resource_type": "file",
  "identifier": "/workspace/outputs/**",
  "normalized_prefix": "/workspace/outputs/",
  "actions": ["read", "write", "create"]
}
```

内核态事件：

```json
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
    "path": "/etc/hosts",
    "tclass": "file",
    "tcontext": "system_u:object_r:net_conf_t:s0"
  },
  "result": {
    "ret": 0,
    "runtime_result": "allow",
    "policy_result": "inferred_allow"
  }
}
```

因为：

```text
/etc/hosts 不以 /workspace/outputs/ 开头
```

所以关联模块不输出关联记录。

## 5. 后续异常检测模块如何使用

异常检测模块后续读取 `correlated_file_events.ndjson`，再自行使用：

```text
第 2 个元素.request.perm
第 1 个元素.actions
```

判断权限是否一致。

也可以使用：

```text
第 2 个元素.target.path
第 1 个元素.identifier
第 1 个元素.normalized_prefix
```

判断资源范围是否一致。

这些判断不在当前关联模块里完成。
