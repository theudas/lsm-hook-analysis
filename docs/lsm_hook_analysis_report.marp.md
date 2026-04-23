---
marp: true
theme: default
paginate: true
size: 16:9
footer: "lsm-hook-analysis | SELinux LSM Hook Event Resolver"
style: |
  section {
    font-family: "Noto Sans CJK SC", "PingFang SC", "Microsoft YaHei", sans-serif;
    font-size: 28px;
    color: #172033;
  }
  h1 {
    color: #0b3d5c;
    font-size: 54px;
    letter-spacing: 0.02em;
  }
  h2 {
    color: #0b3d5c;
    font-size: 40px;
  }
  h3 {
    color: #22577a;
    font-size: 30px;
  }
  code {
    font-family: "JetBrains Mono", "Menlo", "Consolas", monospace;
  }
  pre {
    font-size: 20px;
  }
  table {
    font-size: 23px;
  }
  section.lead {
    background: linear-gradient(135deg, #f7fbff 0%, #e7f1f8 55%, #dbeeea 100%);
  }
  section.inverse {
    background: #0b3d5c;
    color: #f7fbff;
  }
  section.inverse h1,
  section.inverse h2,
  section.inverse h3 {
    color: #f7fbff;
  }
---

<!-- _class: lead -->

# lsm-hook-analysis 实现汇报

面向 SELinux LSM hook 事件的资源访问解析与 JSON 输出

---

## 汇报目标

本次汇报说明当前仓库已经实现的完整能力：

- 项目定位与支持范围
- 用户态 resolver 框架与内核态 CentOS Stream 9 模块
- 输入/输出结构体设计
- 3 类 SELinux hook 的解析逻辑
- `task/cred/inode/file/mask/ret` 如何转成结构化事件
- 外部抓取模块如何调用 resolver API
- debugfs 假事件注入与自测方法
- 当前边界、风险和后续增强方向

---

## 一句话总结

`lsm-hook-analysis` 不负责直接注册或抓取真实 LSM hook。

它负责：

- 接收外部抓取模块传入的 hook 参数和返回值
- 在内核态解析主体、目标资源、权限语义、SELinux context 和路径
- 输出统一结构化事件
- 按需格式化为 JSON

---

## 当前支持的 SELinux Hook

| Hook | 原型 | 当前状态 |
|---|---|---|
| inode permission | `selinux_inode_permission(struct inode *inode, int mask)` | 已支持 |
| file open | `selinux_file_open(struct file *file)` | 已支持 |
| file permission | `selinux_file_permission(struct file *file, int mask)` | 已支持 |

当前没有实现真实 hook 捕获模块。

真实生产链路需要外部模块负责 hook 参数采集。

---

## 当前输出字段

解析后统一输出 `struct lha_enriched_event_v1`：

- `hook` / `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

核心定义位置：

- `include/lha_types.h`
- `kmod/lha_centos9_resolver.h`

---

## 输出结构总览

```text
lha_enriched_event_v1
├── version / hook_id / timestamp_ns
├── hook / hook_signature
├── subject
│   ├── pid / tid / comm
│   └── scontext
├── request
│   ├── mask_raw
│   ├── obj_type
│   └── perm
├── target
│   ├── dev / ino / type / path
│   └── tclass / tcontext
└── result
    ├── ret
    ├── runtime_result
    └── policy_result
```

---

## 代码目录结构

```text
include/
  lha_types.h          公共输入/输出结构
  lha_kernel_api.h     用户态 resolver 的内核抽象接口
  lha_resolver.h       通用 resolver 入口
  lha_json.h           用户态 JSON 接口

src/
  lha_resolver.c       通用解析逻辑
  lha_json.c           用户态 JSON 输出

kmod/
  lha_centos9_resolver.c   CentOS Stream 9 内核态 resolver
  lha_centos9_injector.c   debugfs 假事件注入模块

tests/
  test_resolver.c      mock kernel ops 单元测试
```

---

## 两套实现层次

| 层次 | 代码位置 | 作用 |
|---|---|---|
| 用户态通用框架 | `include/` + `src/` + `tests/` | 固化事件模型、路由逻辑、权限解码和 JSON 格式，便于单测 |
| 内核态运行模块 | `kmod/` | 在 CentOS Stream 9 内核中解析真实 `task/cred/inode/file` |

这样做的好处：

- 解析规则可以先在用户态测试稳定
- 内核态代码只处理真实内核对象和导出 API
- mock 测试不依赖 Linux 内核环境

---

## 当前构建产物

用户态：

```text
build/liblha.a
build/test_resolver
```

内核态：

```text
kmod/lha_centos9_resolver.ko
kmod/lha_centos9_injector.ko
```

`resolver.ko` 是生产 API 模块。

`injector.ko` 仅用于 debugfs 假事件注入和自测。

---

<!-- _class: inverse -->

## 核心数据流

从 hook 参数到 JSON

---

## 总体处理链路

```text
外部抓取模块
  │
  │  1. hook 现场保存 task/cred/inode/file 稳定引用
  │  2. 记录 hook_id / mask / ret / timestamp
  ▼
struct lha_capture_event_v1
  │
  │  workqueue / kthread 可睡眠上下文
  ▼
lha_centos9_resolve_event()
  │
  ├── fill subject
  ├── fill target
  ├── decode request
  └── fill result
  ▼
struct lha_enriched_event_v1
  │
  ▼
lha_centos9_format_json()
  │
  ▼
JSON 输出到调用方通道
```

---

## 输入事件：`lha_capture_event_v1`

输入结构定义：

```c
struct lha_capture_event_v1 {
    uint16_t version;
    uint16_t hook_id;
    uint64_t ts_ns;
    int32_t ret;
    struct {
        const void *task;
        const void *cred;
    } subject;
    union {
        struct { const void *inode; int32_t mask; } inode_permission;
        struct { const void *file; } file_open;
        struct { const void *file; int32_t mask; } file_permission;
    } args;
};
```

位置：`include/lha_types.h`

---

## 输入字段语义

| 字段 | 含义 |
|---|---|
| `version` | 当前固定为 `1` |
| `hook_id` | 3 类 hook 中的一种 |
| `ts_ns` | hook 事件时间戳 |
| `ret` | hook 最终返回值 |
| `subject.task` | hook 现场任务对象 |
| `subject.cred` | hook 现场凭证对象 |
| `args` | 不同 hook 的原始参数 |

重点：`task/cred` 必须来自 hook 现场保存的稳定引用。

---

## `task` 的含义

`task` 对应内核中的 `struct task_struct *`。

它描述“哪个进程/线程触发了这次 hook”。

当前用于解析：

- `pid`：进程 ID，内核态取 `task_tgid_nr(task)`
- `tid`：线程 ID，内核态取 `task_pid_nr(task)`
- `comm`：任务名，内核态取 `task->comm`

实现位置：

- `kmod/lha_centos9_resolver.c:l.187`

---

## `cred` 的含义

`cred` 对应内核中的 `struct cred *`。

它描述“这个任务当时以什么身份访问资源”。

当前主要用于解析 SELinux 主体上下文：

```c
security_cred_getsecid(cred, &secid);
security_secid_to_secctx(secid, &secctx, &secctx_len);
```

输出字段：

```text
subject.scontext
```

示例：`u:r:sshd_t:s0`

---

## 为什么不直接用异步 worker 的 current

resolver 推荐在 workqueue/kthread 中运行。

如果 worker 中再读取：

```c
current
current_cred()
```

拿到的可能是 worker 线程自己，而不是原始触发 hook 的进程。

因此外部抓取模块必须在 hook 现场保存：

- `task`
- `cred`
- `inode` 或 `file`

然后把稳定引用传给 resolver。

---

## 输出事件：`lha_enriched_event_v1`

```c
struct lha_enriched_event_v1 {
    uint16_t version;
    uint16_t hook_id;
    uint64_t timestamp_ns;
    char hook[LHA_MAX_HOOK_LEN];
    char hook_signature[LHA_MAX_SIG_LEN];
    struct lha_subject_v1 subject;
    struct lha_request_v1 request;
    struct lha_target_v1 target;
    struct lha_result_v1 result;
};
```

位置：

- `include/lha_types.h`
- `kmod/lha_centos9_resolver.h`

---

<!-- _class: inverse -->

## Resolver 实现逻辑

入口、路由、字段填充

---

## 用户态通用入口

位置：`src/lha_resolver.c`

入口：

```c
int lha_resolve_event(const struct lha_kernel_ops *ops,
                      const struct lha_capture_event_v1 *event,
                      struct lha_enriched_event_v1 *out)
```

核心动作：

- 校验 `ops/event/out/version`
- 初始化输出结构
- 复制 `version/hook_id/timestamp`
- 根据 `hook_id` switch 路由到具体 resolver

---

## 用户态路由逻辑

```c
switch (event->hook_id) {
case LHA_HOOK_INODE_PERMISSION:
    return resolve_inode_permission(ops, event, out);
case LHA_HOOK_FILE_OPEN:
    return resolve_file_open(ops, event, out);
case LHA_HOOK_FILE_PERMISSION:
    return resolve_file_permission(ops, event, out);
default:
    return -EINVAL;
}
```

位置：`src/lha_resolver.c`

这部分决定了三类 hook 使用不同的参数解析方式。

---

## 用户态为什么有 `lha_kernel_ops`

位置：`include/lha_kernel_api.h`

```c
struct lha_kernel_ops {
    int (*resolve_subject)(...);
    int (*resolve_inode)(...);
    int (*resolve_file)(...);
    int (*sid_to_context)(...);
    int (*sclass_to_string)(...);
    int (*resolve_policy_result)(...);
};
```

作用：

- 通用 resolver 不直接依赖 Linux 内核头文件
- 单测可以用 mock 函数模拟内核对象
- 生产环境由 `kmod/` 直接操作真实内核结构

---

## 内核态生产入口

位置：`kmod/lha_centos9_resolver.c`

```c
int lha_centos9_resolve_event(
    const struct lha_capture_event_v1 *in,
    struct lha_enriched_event_v1 *out)
```

当前导出为 GPL 符号：

```c
EXPORT_SYMBOL_GPL(lha_centos9_resolve_event);
```

外部抓取模块加载后可以直接调用该 API。

---

## 内核态入口校验

`lha_centos9_resolve_event()` 先检查：

- `in != NULL`
- `out != NULL`
- `in->version == 1`
- `in->subject.task != NULL`
- `in->subject.cred != NULL`

然后填基础字段：

```c
out->version = in->version;
out->hook_id = in->hook_id;
out->timestamp_ns = in->ts_ns;
```

失败返回 `-EINVAL`。

---

## 内核态路由

```c
switch (in->hook_id) {
case LHA_HOOK_INODE_PERMISSION:
    return lha_resolve_inode_permission(in, out);
case LHA_HOOK_FILE_OPEN:
    return lha_resolve_file_open(in, out);
case LHA_HOOK_FILE_PERMISSION:
    return lha_resolve_file_permission(in, out);
default:
    return -EINVAL;
}
```

位置：`kmod/lha_centos9_resolver.c`

---

## 字段填充顺序

每个具体 hook resolver 基本遵循同一模板：

```text
1. 写 hook 名称和函数签名
2. fill subject
3. fill target
4. fill request
5. fill result
```

这样 3 类 hook 的输出结构一致，便于上层分析系统消费。

---

## Subject 填充逻辑

位置：`kmod/lha_centos9_resolver.c`

```text
task_struct
  ├── task_tgid_nr(task) -> subject.pid
  ├── task_pid_nr(task)  -> subject.tid
  └── task->comm         -> subject.comm

cred
  └── security_cred_getsecid()
        └── security_secid_to_secctx()
              └── subject.scontext
```

这一步把“谁触发了访问”解析为可读字段。

---

## Target 通用字段

位置：`lha_fill_target_common()`

从 `inode` 提取：

| 输出字段 | 来源 |
|---|---|
| `dev` | `inode->i_sb->s_id` |
| `ino` | `inode->i_ino` |
| `type` | `inode->i_mode` 解码 |
| `tclass` | `inode->i_mode` 解码 |

然后继续解析：

- `path`
- `tcontext`

---

## Target SELinux 上下文

位置：`lha_fill_target_context()`

```c
security_inode_getsecctx(inode, &ctx, &ctx_len);
lha_copy_blob_string(target->tcontext, ...);
security_release_secctx((char *)ctx, ctx_len);
```

输出字段：

```text
target.tcontext
```

示例：`system_u:object_r:etc_t:s0`

---

## Target 路径恢复：file 场景

位置：`lha_fill_target_path_from_file()`

对于 `file_open` 和 `file_permission`：

```c
d_path(&file->f_path, tmp, PATH_MAX);
```

优势：

- `file` 持有 `f_path`
- 可以利用 mount/path 上下文恢复更接近用户态看到的路径
- 通常比只有 `inode` 更可靠

---

## Target 路径恢复：inode 场景

位置：`lha_fill_target_path_from_inode()`

对于 `inode_permission`：

```c
alias = d_find_alias(inode);
dentry_path_raw(alias, tmp, PATH_MAX);
```

现实边界：

- `inode` 本身不携带完整 mount/path 上下文
- 只能 best effort
- 无法恢复时退化为 basename 或 `<unknown>`

---

## 文件类型映射

`inode->i_mode` 会被映射为两类语义：

| 文件系统类型 | `target.type` / `request.obj_type` | `target.tclass` |
|---|---|---|
| regular file | `reg` | `file` |
| directory | `dir` | `dir` |
| symlink | `lnk` | `lnk_file` |
| char device | `chr` | `chr_file` |
| block device | `blk` | `blk_file` |
| fifo | `fifo` | `fifo_file` |
| socket | `sock` | `sock_file` |

实现位置：`mode_to_obj_type()` / `mode_to_tclass()`

---

## Request 权限解码

权限字符串输出到：

```text
request.perm
```

基本规则：

| 输入 bit | 普通文件 | 目录 |
|---|---|---|
| `MAY_READ` | `read` | `read` |
| `MAY_WRITE` | `write` | `write` |
| `MAY_EXEC` | `exec` | `search` |
| `MAY_APPEND` | `append` | 当前目录逻辑不单独输出 |

多个权限用 `|` 拼接。

---

## `file_open` 权限解码

`selinux_file_open(struct file *file)` 没有 `mask` 参数。

因此 resolver 根据 `file->f_flags` 推导：

```text
O_RDONLY -> open|read
O_WRONLY -> open|write
O_RDWR   -> open|read|write
O_APPEND -> open|append
O_EXEC   -> open|exec 或 open|search
```

当前输出：

```text
request.mask_raw = 0
```

---

## `file_permission` 的 append 修正

`selinux_file_permission(struct file *file, int mask)` 有 `mask`。

但如果：

```text
file->f_flags 包含 O_APPEND
mask 包含 MAY_WRITE
```

resolver 会把有效权限修正为：

```text
append
```

实现位置：

```c
if ((file->f_flags & O_APPEND) && (effective_mask & LHA_MAY_WRITE))
    effective_mask |= LHA_MAY_APPEND;
```

---

## Result 填充逻辑

`result.ret` 直接来自 hook 返回值。

`runtime_result` 由返回值分类：

| `ret` | `runtime_result` |
|---|---|
| `0` | `allow` |
| `-EACCES` | `deny` |
| 其他负值 | `error` |

当前 CentOS 9 内核模块：

```text
policy_result = unknown
```

原因：策略层面的真实 allow/deny 还没有稳定获取方案。

---

<!-- _class: inverse -->

## 三类 Hook 解析细节

每个 hook 的输入、处理和输出

---

## 1. inode_permission

输入：

```c
struct inode *inode
int mask
int ret
task / cred
```

处理：

- `target` 从 `inode` 解析
- `path` 用 `d_find_alias()` + `dentry_path_raw()` best effort 恢复
- `request.mask_raw = mask`
- `request.perm` 根据 `mask + inode->i_mode` 解码

典型输出：

```text
hook = selinux_inode_permission
perm = search / read / write / exec
```

---

## inode_permission 调用链

```text
lha_centos9_resolve_event()
  └── lha_resolve_inode_permission()
        ├── lha_fill_subject()
        ├── lha_fill_target_from_inode()
        │     ├── lha_fill_target_common()
        │     ├── lha_fill_target_context()
        │     └── lha_fill_target_path_from_inode()
        ├── lha_decode_mask_perm()
        └── lha_fill_result()
```

对应代码：

- `kmod/lha_centos9_resolver.c`

---

## 2. file_open

输入：

```c
struct file *file
int ret
task / cred
```

处理：

- `target` 从 `file_inode(file)` 和 `file->f_path` 解析
- `request.mask_raw = 0`
- `request.perm` 从 `file->f_flags` 推导
- 默认包含 `open`

典型输出：

```text
hook = selinux_file_open
perm = open|read
```

---

## file_open 调用链

```text
lha_centos9_resolve_event()
  └── lha_resolve_file_open()
        ├── file_inode(file)
        ├── lha_fill_subject()
        ├── lha_fill_target_from_file()
        │     ├── lha_fill_target_common()
        │     ├── lha_fill_target_context()
        │     └── lha_fill_target_path_from_file()
        ├── lha_decode_file_open_perm()
        └── lha_fill_result()
```

路径恢复核心：

```c
d_path(&file->f_path, tmp, PATH_MAX)
```

---

## 3. file_permission

输入：

```c
struct file *file
int mask
int ret
task / cred
```

处理：

- `target` 从 `file` 解析
- `request.mask_raw = mask`
- `request.perm` 根据 `mask + file->f_flags + inode->i_mode` 解码
- 如果 `O_APPEND + MAY_WRITE`，输出 `append`

典型输出：

```text
hook = selinux_file_permission
perm = append
runtime_result = deny
```

---

## file_permission 调用链

```text
lha_centos9_resolve_event()
  └── lha_resolve_file_permission()
        ├── file_inode(file)
        ├── lha_fill_subject()
        ├── lha_fill_target_from_file()
        ├── 修正 O_APPEND + MAY_WRITE -> MAY_APPEND
        ├── lha_decode_mask_perm()
        └── lha_fill_result()
```

这一分支最能体现“不能只看 mask，还要结合 file 状态”。

---

<!-- _class: inverse -->

## JSON 输出实现

结构化事件转字符串

---

## JSON 接口

用户态：

```c
int lha_event_to_json(const struct lha_enriched_event_v1 *event,
                      char *buf,
                      size_t buf_len);
```

内核态：

```c
int lha_centos9_format_json(const struct lha_enriched_event_v1 *event,
                            char *buf,
                            size_t buf_len);
```

内核态符号：

```c
EXPORT_SYMBOL_GPL(lha_centos9_format_json);
```

---

## JSON 拼接策略

实现方式：

- 自己维护 `offset`
- 使用 `appendf()` 按字段追加
- 使用 `append_json_string()` 对字符串转义
- 输出固定结构，不依赖第三方 JSON 库

已处理的转义：

- `\`
- `"`
- `\b`
- `\f`
- `\n`
- `\r`
- `\t`
- 控制字符 `\u00xx`

---

## JSON 结构示意

```json
{
  "hook": "selinux_file_open",
  "hook_signature": "static int selinux_file_open(struct file *file)",
  "timestamp_ns": 123456789,
  "subject": {
    "pid": 1000,
    "tid": 1000,
    "scontext": "u:r:xxx_t:s0",
    "comm": "demo"
  },
  "request": {
    "mask_raw": 0,
    "obj_type": "reg",
    "perm": "open|read"
  }
}
```

完整 JSON 还包括 `target` 和 `result`。

---

## JSON 输出字段的消费价值

| 分组 | 用途 |
|---|---|
| `hook` | 还原触发点 |
| `subject` | 定位发起进程和 SELinux 主体 |
| `request` | 分析访问意图 |
| `target` | 定位被访问资源 |
| `result` | 判断运行时允许、拒绝或错误 |

这为后续异常行为分析提供统一输入格式。

---

<!-- _class: inverse -->

## 外部调用方法

真实抓取模块如何接入

---

## 对外 API

头文件：

```text
kmod/lha_centos9_resolver.h
```

导出符号：

```c
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
                              struct lha_enriched_event_v1 *out);

int lha_centos9_format_json(const struct lha_enriched_event_v1 *event,
                            char *buf,
                            size_t buf_len);
```

要求：调用方模块需要 GPL 兼容。

---

## 生产推荐调用链路

```text
1. 真实 hook 现场拿到参数和返回值
2. 保存 task / cred / inode / file 的稳定引用
3. 组装 struct lha_capture_event_v1
4. 把事件放入 workqueue / kthread
5. worker 中调用 lha_centos9_resolve_event()
6. 如需字符串，调用 lha_centos9_format_json()
7. 把 JSON 送到 debugfs/procfs/netlink/relayfs/trace buffer
8. 释放此前保存的引用
```

不建议在原始 hook 回调中直接解析全部字段。

---

## 为什么推荐 workqueue/kthread

resolver 内部可能调用：

```text
security_secid_to_secctx()
security_inode_getsecctx()
d_path()
kmalloc(GFP_KERNEL)
```

这些操作可能睡眠或分配内存。

因此推荐：

- hook 现场只做轻量捕获
- 后续解析放到可睡眠上下文

这样更符合内核上下文约束，也更安全。

---

## 稳定引用要求

外部抓取方需要在 hook 现场建立引用：

| 对象 | 建立引用 | 释放引用 |
|---|---|---|
| `task` | `get_task_struct()` | `put_task_struct()` |
| `cred` | `get_cred()` / `get_current_cred()` | `put_cred()` |
| `inode` | `igrab()` / `ihold()` | `iput()` |
| `file` | `get_file()` | `fput()` |

原因：resolver 可能异步执行，裸指针可能已经失效。

---

## 外部填充：inode_permission

```c
event.version = 1;
event.hook_id = LHA_HOOK_INODE_PERMISSION;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

event.args.inode_permission.inode = igrab(inode);
event.args.inode_permission.mask = mask;
```

注意：调用方负责后续释放引用。

---

## 外部填充：file_open

```c
event.version = 1;
event.hook_id = LHA_HOOK_FILE_OPEN;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

get_file(file);
event.args.file_open.file = file;
```

`file_open` 没有 `mask` 参数。

---

## 外部填充：file_permission

```c
event.version = 1;
event.hook_id = LHA_HOOK_FILE_PERMISSION;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

get_file(file);
event.args.file_permission.file = file;
event.args.file_permission.mask = mask;
```

resolver 会结合 `file->f_flags` 修正 append 语义。

---

## Worker 中调用 resolver

```c
static void my_resolve_worker(struct work_struct *work)
{
    struct my_pending_event *p =
        container_of(work, struct my_pending_event, work);
    struct lha_enriched_event_v1 out;
    char json[8192];
    int rc;

    rc = lha_centos9_resolve_event(&p->ev, &out);
    if (!rc) {
        rc = lha_centos9_format_json(&out, json, sizeof(json));
        if (!rc)
            pr_info("resolved event: %s\n", json);
    }

    my_release_capture_refs(&p->ev);
    kfree(p);
}
```

---

## 外部调用注意事项

- `version` 必须填 `1`
- `subject.task` 和 `subject.cred` 不能为空
- 三类 hook 必须填对应 union 分支
- `lha_centos9_resolve_event()` 成功返回 `0`
- 失败返回负错误码，例如 `-EINVAL`
- `lha_centos9_format_json()` 需要调用方提供足够大的缓冲区
- injector 里的释放函数是 `static`，外部模块不能直接复用，需要自行实现

---

<!-- _class: inverse -->

## 假事件注入测试

debugfs injector 验证完整链路

---

## 为什么需要 injector

当前项目不负责真实 LSM hook 捕获。

为了验证 resolver 是否能工作，提供了：

```text
kmod/lha_centos9_injector.ko
```

它做的事情：

- 创建 debugfs 入口
- 构造 3 类假事件
- 调用 resolver 导出的 API
- 保存最近一次 JSON

它不是生产入口。

---

## injector 暴露的 debugfs 文件

加载 `lha_centos9_injector.ko` 后创建：

```text
/sys/kernel/debug/lha_centos9/inject
/sys/kernel/debug/lha_centos9/last_json
```

含义：

- `inject`：写入测试命令，触发假事件注入
- `last_json`：读取最近一次 resolver 生成的 JSON

实现位置：

- `kmod/lha_centos9_injector.c`

---

## injector 内部调用链

```text
用户写 debugfs: inject
  │
  ▼
lha_inject_write()
  │
  ├── sample_inode  -> lha_inject_sample_inode_permission()
  ├── sample_open   -> lha_inject_sample_file_open()
  └── sample_append -> lha_inject_sample_file_permission()
        │
        ▼
lha_run_injected_event()
  ├── lha_centos9_resolve_event()
  ├── lha_centos9_format_json()
  └── lha_store_last_json()
```

---

## 假事件 1：sample_inode

命令：

```bash
echo sample_inode | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

构造内容：

- hook：`selinux_inode_permission`
- 目标：`/tmp`
- 参数：`mask = LHA_MAY_EXEC`
- 返回值：`ret = 0`

验证点：

- inode 路径恢复
- 目录 `MAY_EXEC -> search`
- subject/target SELinux context

---

## 假事件 2：sample_open

命令：

```bash
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

构造内容：

- hook：`selinux_file_open`
- 目标：`/etc/hosts`
- 打开方式：`O_RDONLY`
- 返回值：`ret = 0`

验证点：

- `file *` 路径恢复
- `open|read` 权限语义
- JSON 输出完整性

---

## 假事件 3：sample_append

命令：

```bash
echo sample_append | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

构造内容：

- hook：`selinux_file_permission`
- 目标：`/tmp/lha_inject.log`
- 打开方式：`O_CREAT | O_WRONLY | O_APPEND`
- 参数：`mask = LHA_MAY_WRITE`
- 返回值：`ret = -EACCES`

验证点：

- `MAY_WRITE + O_APPEND -> append`
- `-EACCES -> runtime_result=deny`

---

## injector 的引用管理

injector 自己构造事件时，也遵循稳定引用规则：

```text
task  -> get_task_struct(current)
cred  -> get_current_cred()
inode -> igrab()
file  -> filp_open() 后保留 file 引用
```

结束后释放：

```text
task  -> put_task_struct()
cred  -> put_cred()
inode -> iput()
file  -> fput()
```

实现位置：`lha_release_capture_refs()`

---

## 完整内核态自测步骤

```bash
cd kmod
make

sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko

sudo mount -t debugfs none /sys/kernel/debug
ls -l /sys/kernel/debug/lha_centos9

echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

预期能看到结构化 JSON。

---

## 模块卸载顺序

```bash
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_resolver
```

原因：

- injector 依赖 resolver 导出的符号
- 必须先卸载依赖方，再卸载被依赖方

检查：

```bash
lsmod | grep lha
dmesg | tail
```

---

<!-- _class: inverse -->

## 用户态测试

mock kernel ops 验证解析规则

---

## 用户态构建与测试

根目录执行：

```bash
make
make test
```

产物：

```text
build/liblha.a
build/test_resolver
```

`make test` 会运行：

```text
tests/test_resolver.c
```

成功输出：

```text
ok
```

---

## 用户态测试覆盖点

`tests/test_resolver.c` 使用 mock `lha_kernel_ops` 覆盖：

- `inode_permission` 路由
- `file_open` 路由
- `file_permission` 路由
- subject 填充
- target 填充
- `sid -> context`
- `sclass -> string`
- 权限解码
- `runtime_result`
- `policy_result`
- JSON 字段输出

---

## 典型测试断言

`inode_permission`：

```text
目录 + MAY_EXEC -> search
ret = 0 -> allow
```

`file_open`：

```text
read file -> open|read
JSON 中包含 selinux_file_open
```

`file_permission`：

```text
O_APPEND + MAY_WRITE -> append
ret = -13 -> deny
```

这些断言保证核心解析语义稳定。

---

<!-- _class: inverse -->

## 部署与运行

CentOS Stream 9 内核态执行路径

---

## 用户态验证环境

需要：

- `make`
- C 编译器，例如 `cc` 或 `gcc`

不需要：

- Linux kernel headers
- root 权限
- SELinux 环境

目的：

- 快速验证通用解析逻辑
- 在开发机上跑单元测试

---

## 内核态运行环境

需要：

- Linux 环境，推荐 CentOS Stream 9
- root/sudo 权限
- 当前运行内核对应的构建目录
- 内核模块构建工具链

通常需要存在：

```bash
/lib/modules/$(uname -r)/build
```

macOS 不能加载 Linux `.ko`。

---

## 内核模块编译

```bash
cd kmod
make
```

默认使用：

```make
KDIR ?= /lib/modules/$(shell uname -r)/build
```

也可以指定：

```bash
make KDIR=/path/to/kernel/build
```

生成：

```text
lha_centos9_resolver.ko
lha_centos9_injector.ko
```

---

## 生产最小加载

生产环境只需要：

```bash
sudo insmod lha_centos9_resolver.ko
```

然后加载外部真实抓取模块。

典型顺序：

```text
1. lha_centos9_resolver.ko
2. your_hook_capture.ko
3. 外部模块调用 resolver API
```

不需要加载 `lha_centos9_injector.ko`。

---

## 自测加载

自测时加载两个模块：

```bash
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko
```

检查：

```bash
lsmod | grep lha
dmesg | tail
```

预期：

```text
lha_centos9_injector
lha_centos9_resolver
```

---

<!-- _class: inverse -->

## 当前边界

已知限制和设计取舍

---

## 不负责真实 hook 捕获

当前项目明确不实现：

- 注册 SELinux hook
- kprobe/ftrace/eBPF 捕获
- hook 返回值采集
- 真实事件队列管理
- 输出通道管理

这些职责属于外部抓取模块。

本项目专注：

- 事件解析
- 语义补齐
- 结构化输出

---

## 路径恢复边界

`file *` 路径：

- 通过 `file->f_path` + `d_path()`
- 通常比较可靠

`inode *` 路径：

- 通过 `d_find_alias()` + `dentry_path_raw()`
- 没有完整 mount/path 上下文
- 只能 best effort

因此：

- `file_open/file_permission` 路径更可信
- `inode_permission` 路径需要谨慎解释

---

## policy_result 当前边界

当前字段：

```text
policy_result = unknown
```

原因：

- `ret` 不一定等同于 SELinux policy 结果
- permissive 模式下 policy deny 也可能 runtime allow
- 稳定读取 AVC/SELinux 策略结论还未实现

后续可增强：

- 结合 AVC 审计事件
- 结合 SELinux decision 路径
- 增加 policy-level 判定能力

---

## 上下文与内存约束

resolver 设计为在可睡眠上下文运行。

需要避免：

- 在不可睡眠上下文调用可能睡眠的函数
- 异步传递裸指针
- 忘记释放引用
- buffer 太小导致 JSON 截断风险

当前建议：

- hook 现场轻量捕获
- worker 中解析
- 调用方负责生命周期管理

---

## 当前实现价值

已经完成：

- v1 输入/输出接口
- 3 类 hook 路由
- 主体信息解析
- 目标资源解析
- SELinux context 解析
- 路径恢复
- 权限语义解码
- 运行时结果分类
- JSON 输出
- 用户态单测
- 内核态 debugfs 假事件注入

---

## 后续增强方向

建议后续工作：

- 接入真实 hook 抓取模块
- 增加事件队列和输出通道
- 增强 `policy_result`
- 增加更多 hook 类型
- 增强路径唯一性和 mount namespace 语义
- 增加 JSON buffer 长度检查和错误返回精细化
- 增加内核态自动化测试脚本
- 增加版本兼容矩阵

---

<!-- _class: lead -->

# 总结

当前项目已经形成“外部捕获 + 内核态解析 + 统一 JSON 输出”的 resolver 能力。

下一步重点是接入真实 hook 采集模块，并完善策略结果与生产级输出通道。

