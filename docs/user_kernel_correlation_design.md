# 用户态与内核态离线关联设计

## 1. 背景与模块边界

本文档描述在当前项目约束下，用户态 IR 策略与内核态 LSM 事件如何进行离线关联，并明确区分“关联模块”和“异常检测模块”的职责。

核心原则：

```text
关联模块只产出匹配事实，不产出异常结论。
异常检测模块基于关联事实判断是否越权或异常。
```

因此，关联模块不应该直接输出：

```text
authorized
permission_exceeded
resource_out_of_scope
```

这些属于异常检测模块的判定结果。

关联模块应该回答的是：

```text
这条内核态 LSM 文件访问事件，能否在用户态 IR 中找到相关 file policy？
如果能，命中了哪些 policy？
匹配依据是什么？
是否存在歧义？
```

异常检测模块再回答：

```text
内核访问路径是否超出用户态允许资源范围？
内核请求权限是否超出用户态允许权限集合？
这次访问应该被标记为正常、异常、低置信还是待审计？
```

## 2. 当前约束

用户态目前只能提供类似下面的策略 JSON：

```json
{
  "policies": [
    {
      "subject": "waimai",
      "objects": [
        {
          "type": "tool",
          "identifier": "meituan",
          "params": [
            {
              "name": "city",
              "identifier": "北京"
            }
          ]
        },
        {
          "type": "tool",
          "identifier": "eleme"
        }
      ],
      "effect": "allow"
    },
    {
      "subject": "file",
      "object": {
        "type": "file",
        "identifier": "/workspace/outputs/**"
      },
      "action": ["read", "write", "create"],
      "effect": "allow"
    }
  ]
}
```

该输入有几个重要限制：

- 用户态不能提供 `pid` / `tid`。
- 用户态不能提供 query id / task id。
- 用户态不能提供可靠的用户任务时间戳。
- `tool` 资源目前没有稳定的 `tool -> kernel resource` 映射。
- LSM Hook 侧当前可稳定解析的是文件系统相关访问事件。

因此，当前阶段不做 query/task/pid 级归因，只做 file policy 与 kernel file event 的离线匹配。

## 3. 推荐链路

整体链路分成两个模块：

```text
用户态 IR JSON
    -> policy 归一化
    -> file policy index
    -> 用户态-内核态关联模块
    -> correlated_kernel_events.ndjson
    -> 异常检测模块
    -> anomaly_events.ndjson
```

其中：

- 关联模块输出 `correlated_kernel_events.ndjson`
  只描述内核事件与用户态 policy 的候选匹配关系。
- 异常检测模块输出 `anomaly_events.ndjson`
  描述是否越界、越了什么界、风险等级和原因。

## 4. 用户态策略归一化

关联模块首先从用户态 JSON 中筛选可用于内核态文件访问匹配的策略。

### 4.1 file 策略

原始策略：

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

归一化后：

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

说明：

- `policy_ref` 用于回溯原始 JSON 位置。
- `identifier` 保留用户态原始资源表达。
- `normalized_prefix` 用于快速做路径前缀匹配。
- `actions` 是用户态声明的允许权限集合，但关联模块不判断权限是否越界。

### 4.2 tool 策略

原始策略：

```json
{
  "subject": "waimai",
  "objects": [
    {
      "type": "tool",
      "identifier": "meituan"
    }
  ],
  "effect": "allow"
}
```

归一化后：

```json
{
  "policy_ref": "policies[0].objects[0]",
  "subject": "waimai",
  "effect": "allow",
  "resource_type": "tool",
  "identifier": "meituan",
  "kernel_mappable": false,
  "reason": "no_tool_to_kernel_resource_mapping"
}
```

当前阶段 `tool` 策略不参与 LSM 文件事件匹配，只在策略索引或统计摘要中保留。后续如果能建立 `tool -> exe/process/SELinux label/kernel resource` 映射表，再扩展 tool 相关关联逻辑。

## 5. 内核态事件依赖字段

关联模块主要依赖 LSM 解析事件中的以下字段。

用于事件标识和审计：

```text
timestamp_ns
subject.pid
subject.tid
subject.comm
subject.scontext
hook
```

用于资源匹配：

```text
target.type
target.path
target.tclass
```

用于权限透传：

```text
request.perm
result.runtime_result
result.policy_result
```

注意：

- `request.perm` 需要透传给异常检测模块，但关联模块不做 `request.perm ⊆ policy.actions` 的判定。
- `runtime_result` / `policy_result` 也只透传，不参与关联模块的异常判定。

## 6. 关联模块的匹配规则

### 6.1 资源类型过滤

v1 只处理文件系统相关内核事件。

如果内核事件不是当前支持的文件资源类型，关联模块输出：

```text
correlation_status = unsupported_resource_type
```

### 6.2 路径候选匹配

关联模块使用用户态 file policy 的 `normalized_prefix` 与内核态 `target.path` 做路径匹配。

例如用户态策略：

```text
/workspace/outputs/**
```

归一化为：

```text
/workspace/outputs/
```

内核态路径：

```text
/workspace/outputs/week_report.md
```

则该 policy 成为候选策略。

### 6.3 最长前缀选择

如果多条策略匹配同一路径，关联模块按最长前缀排序。

示例：

```text
/workspace/**
/workspace/outputs/**
```

路径：

```text
/workspace/outputs/week_report.md
```

优先候选为：

```text
/workspace/outputs/**
```

如果只有一个最长前缀候选，则：

```text
correlation_status = correlated
```

如果多个候选具有相同最长前缀，且无法唯一选择，则：

```text
correlation_status = ambiguous
```

如果没有任何 file policy 匹配路径，则：

```text
correlation_status = no_policy_candidate
```

`no_policy_candidate` 不是异常结论，它只表示关联模块没有找到能解释该路径的用户态 file policy。是否将其视为资源越界，由异常检测模块决定。

## 7. 关联模块输出

关联模块主输出建议采用 NDJSON：

```text
correlated_kernel_events.ndjson
```

一行表示一条内核事件的关联结果。

### 7.1 唯一关联成功

```json
{
  "event_id": "k_000001",
  "correlation_status": "correlated",
  "kernel_event": {
    "timestamp_ns": 1779612350123456789,
    "pid": 12345,
    "tid": 12346,
    "comm": "agent_worker",
    "scontext": "system_u:system_r:container_t:s0",
    "hook": "inode_permission",
    "target_type": "file",
    "target_path": "/workspace/outputs/week_report.md",
    "target_tclass": "file",
    "request_perm": ["write"],
    "runtime_result": "allow",
    "policy_result": "allow"
  },
  "selected_policy": {
    "policy_ref": "policies[1]",
    "subject": "file",
    "effect": "allow",
    "resource_type": "file",
    "identifier": "/workspace/outputs/**",
    "normalized_prefix": "/workspace/outputs/",
    "actions": ["read", "write", "create"],
    "match_type": "longest_prefix"
  },
  "candidate_policies": [
    {
      "policy_ref": "policies[1]",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read", "write", "create"],
      "prefix_length": 19
    }
  ],
  "correlation_evidence": {
    "resource_type_supported": true,
    "path_candidate_count": 1,
    "selection_rule": "longest_prefix",
    "unmatched_reason": null
  }
}
```

这里即使 `request_perm` 是 `write`，`actions` 包含 `write`，关联模块也不输出 `perm_contained = true`。这个集合包含判断属于异常检测模块。

### 7.2 没有策略候选

```json
{
  "event_id": "k_000002",
  "correlation_status": "no_policy_candidate",
  "kernel_event": {
    "timestamp_ns": 1779612351123456789,
    "pid": 12345,
    "tid": 12346,
    "comm": "agent_worker",
    "scontext": "system_u:system_r:container_t:s0",
    "hook": "inode_permission",
    "target_type": "file",
    "target_path": "/workspace/private/secrets.txt",
    "target_tclass": "file",
    "request_perm": ["read"],
    "runtime_result": "allow",
    "policy_result": "allow"
  },
  "selected_policy": null,
  "candidate_policies": [],
  "correlation_evidence": {
    "resource_type_supported": true,
    "path_candidate_count": 0,
    "selection_rule": "longest_prefix",
    "unmatched_reason": "no_file_policy_matches_target_path"
  }
}
```

这里关联模块只说明“没找到用户态策略候选”。异常检测模块可以进一步判定为资源越界或高风险事件。

### 7.3 多策略歧义

```json
{
  "event_id": "k_000003",
  "correlation_status": "ambiguous",
  "kernel_event": {
    "timestamp_ns": 1779612352123456789,
    "pid": 12345,
    "tid": 12346,
    "comm": "agent_worker",
    "scontext": "system_u:system_r:container_t:s0",
    "hook": "file_permission",
    "target_type": "file",
    "target_path": "/workspace/outputs/week_report.md",
    "target_tclass": "file",
    "request_perm": ["write"],
    "runtime_result": "allow",
    "policy_result": "allow"
  },
  "selected_policy": null,
  "candidate_policies": [
    {
      "policy_ref": "policies[1]",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read", "write"],
      "prefix_length": 19
    },
    {
      "policy_ref": "policies[2]",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read"],
      "prefix_length": 19
    }
  ],
  "correlation_evidence": {
    "resource_type_supported": true,
    "path_candidate_count": 2,
    "selection_rule": "longest_prefix",
    "unmatched_reason": "multiple_policies_with_same_prefix_length"
  }
}
```

异常检测模块可以根据自身策略选择：

- 保守处理为待审计。
- 使用任一候选允许即可放行。
- 使用所有候选都允许才认为正常。
- 按策略优先级字段扩展后重新判断。

## 8. `correlation_status` 定义

关联模块建议固定输出以下状态：

```text
correlated
no_policy_candidate
ambiguous
no_user_file_policy
unsupported_resource_type
invalid_event
```

含义如下：

- `correlated`
  找到唯一最优 file policy 候选。
- `no_policy_candidate`
  用户态存在 file policy，但没有任何 policy 匹配当前内核路径。
- `ambiguous`
  多条 policy 以同等优先级匹配当前内核路径，无法唯一选择。
- `no_user_file_policy`
  用户态 JSON 中没有任何可用于文件事件匹配的 file policy。
- `unsupported_resource_type`
  内核事件不是当前 v1 支持的文件资源类型。
- `invalid_event`
  内核事件缺少必要字段，例如 `target.path` 为空或无法解析。

这些状态描述的是关联质量，不描述是否越权。

## 9. 策略索引输出

关联模块可以额外输出归一化策略索引：

```text
policy_index.json
```

示例：

```json
{
  "file_policies": [
    {
      "policy_ref": "policies[1]",
      "subject": "file",
      "effect": "allow",
      "resource_type": "file",
      "identifier": "/workspace/outputs/**",
      "normalized_prefix": "/workspace/outputs/",
      "actions": ["read", "write", "create"]
    }
  ],
  "tool_policies": [
    {
      "policy_ref": "policies[0].objects[0]",
      "subject": "waimai",
      "effect": "allow",
      "resource_type": "tool",
      "identifier": "meituan",
      "kernel_mappable": false,
      "reason": "no_tool_to_kernel_resource_mapping"
    }
  ]
}
```

## 10. 关联摘要输出

关联模块可以输出批次级摘要：

```text
correlation_summary.json
```

示例：

```json
{
  "batch": {
    "date": "2026-05-24",
    "kernel_event_count": 120000
  },
  "user_policy": {
    "file_policy_count": 1,
    "tool_policy_count": 2,
    "kernel_mappable_tool_count": 0
  },
  "correlation_result": {
    "correlated_count": 93000,
    "no_policy_candidate_count": 3200,
    "ambiguous_count": 0,
    "no_user_file_policy_count": 0,
    "unsupported_resource_type_count": 18000,
    "invalid_event_count": 0
  },
  "top_no_policy_candidate_paths": [
    "/etc/passwd",
    "/workspace/private/secrets.txt"
  ]
}
```

摘要只描述关联效果，不统计 `permission_exceeded_count` 这类异常检测结论。

## 11. 异常检测模块如何消费

异常检测模块读取：

```text
correlated_kernel_events.ndjson
```

然后自行完成权限和异常判断。

基础逻辑可以是：

```text
correlation_status == correlated
    -> 比较 kernel_event.request_perm 与 selected_policy.actions

correlation_status == no_policy_candidate
    -> 可判定为资源范围外访问候选

correlation_status == no_user_file_policy
    -> 可判定为高风险候选

correlation_status == ambiguous
    -> 按检测策略处理为待审计或低置信异常

correlation_status == unsupported_resource_type
    -> 暂不判断

correlation_status == invalid_event
    -> 数据质量问题或待审计
```

权限判断使用集合包含关系：

```text
normalized_kernel_perm ⊆ selected_policy.actions
```

异常检测模块可以输出自己的结果，例如：

```json
{
  "event_id": "k_000003",
  "anomaly_status": "permission_exceeded",
  "severity": "high",
  "basis": {
    "correlation_status": "correlated",
    "target_path": "/workspace/outputs/week_report.md",
    "kernel_perm": ["exec"],
    "user_allowed_actions": ["read", "write", "create"],
    "runtime_result": "allow",
    "policy_result": "allow"
  }
}
```

## 12. 权限名称对齐

权限名称对齐建议放在异常检测模块，或作为异常检测模块独立加载的配置。

内核态 resolver 当前可能输出：

```text
open
read
write
append
exec
search
```

用户态策略当前可能输出：

```text
read
write
create
delete
update
```

v1 可先维护一张简单映射表：

```text
open   -> read
read   -> read
write  -> write
append -> write
exec   -> execute
search -> read
```

说明：

- `open` 在没有更细粒度上下文时，可先按 `read` 保守处理。
- `append` 可先并入 `write`。
- `search` 多见于目录访问，可先按目录 `read` / `search` 单独观察，后续再决定是否暴露给用户态 IR。
- `create` 在部分 hook 中可能表现为目录写权限或后续文件写权限，v1 可以先通过 `write` 近似处理。

该映射会影响异常检测结论，因此不建议由关联模块内置并直接产出异常判定。

## 13. 后续扩展方向

后续如果用户态能提供更多锚点，可以逐步增强关联能力：

- 用户会话 id。
- agent run id。
- workspace id。
- sandbox/container id。
- 用户态任务开始/结束时间。
- tool 的 `source` / exe 路径。
- `tool -> process/SELinux label/kernel resource` 映射表。

在这些信息稳定之前，建议保持当前 v1 边界：

```text
关联模块：只产出 kernel event 与 user file policy 的候选匹配关系。
异常检测模块：基于关联结果判断资源越界、权限越界和风险等级。
```
