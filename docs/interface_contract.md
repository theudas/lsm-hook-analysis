# LSM Hook Analysis 接口文档

## 1. 目标

本文档定义 `lsm-hook-analysis` 的 v1 接口约束，目标是把外部抓取到的 3 个 SELinux hook 参数与返回值，解析成统一的 JSON 结果。

本项目不负责抓 hook，本项目负责：

- 接收外部提供的 hook 参数和返回值
- 在内核态补齐 `current`、`cred`、SELinux context、目标对象信息
- 根据不同 hook 路由到不同解析函数
- 输出统一结构化结果

## 2. 已知前提

外部只能提供以下 3 个 hook 的参数和返回值：

- `static int selinux_inode_permission(struct inode *inode, int mask)`
- `static int selinux_file_open(struct file *file)`
- `static int selinux_file_permission(struct file *file, int mask)`

除此之外，其他字段都由本项目自己在内核态补齐。

这里直接采用以下实现假设：

- 外部抓取方能稳定把 hook 参数和返回值交给本项目
- resolver 运行在 hook 之后
- resolver 仍然可以在内核态访问这些 hook 参数对应的对象
- 外部除了 `inode/file` 外，还会传入 hook 当时对应的稳定 `task/cred` 引用

不再讨论“外部抓取是否稳定”这个问题，直接假设它成立。

## 3. 总体处理链路

v1 推荐链路：

1. 外部模块抓到 hook 参数与最终返回值
2. 本项目接收原始输入
3. 根据 hook 类型路由到不同 resolver
4. resolver 在内核态读取：
   - `current`
   - `current_cred()`
   - `inode` / `file`
   - SELinux 安全属性
5. 将结果组织成统一事件
6. 序列化为 JSON

## 4. 输入接口

### 4.1 输入范围

v1 输入只要求携带：

- hook 类型
- hook 参数
- hook 最终返回值
- 事件时间戳
- 稳定的 `task` / `cred` 引用

建议统一成如下输入结构：

```c
enum lha_hook_id {
    LHA_HOOK_INODE_PERMISSION = 1,
    LHA_HOOK_FILE_OPEN = 2,
    LHA_HOOK_FILE_PERMISSION = 3,
};

struct lha_capture_event_v1 {
    __u16 version;
    __u16 hook_id;
    __u64 ts_ns;
    __s32 ret;

    struct {
        struct task_struct *task;
        const struct cred *cred;
    } subject;

    union {
        struct {
            struct inode *inode;
            __s32 mask;
        } inode_permission;

        struct {
            struct file *file;
        } file_open;

        struct {
            struct file *file;
            __s32 mask;
        } file_permission;
    } args;
};
```

### 4.2 字段说明

- `version`
  接口版本，v1 固定为 `1`
- `hook_id`
  表示 3 种 hook 里的哪一种
- `ts_ns`
  事件时间戳，建议使用 ns 级时间
- `ret`
  hook 最终返回值
- `subject.task`
  hook 现场对应任务的稳定引用
- `subject.cred`
  hook 现场对应 cred 的稳定引用
- `args`
  对应 hook 的原始参数

## 5. 路由规则

收到输入后，必须按 `hook_id` 路由到不同函数：

- `LHA_HOOK_INODE_PERMISSION`
  路由到 `resolve_inode_permission()`
- `LHA_HOOK_FILE_OPEN`
  路由到 `resolve_file_open()`
- `LHA_HOOK_FILE_PERMISSION`
  路由到 `resolve_file_permission()`

建议统一入口如下：

```c
int lha_resolve_event(const struct lha_capture_event_v1 *in,
                      struct lha_enriched_event_v1 *out);
```

内部由 `lha_resolve_event()` 进行 switch 分发。

## 6. subject 字段定义

`subject` 表示执行该 hook 的任务，但它不是在 resolver 运行时再现取的，而是使用外部在 hook 现场稳定保存下来的 `task/cred` 引用。

### 6.1 pid / tid

字段：

- `pid`
- `tid`

语义：

- `pid` 表示进程 id，实际取 `tgid`
- `tid` 表示线程 id，实际取当前线程 id

实现来源：

- `pid` 从传入 `task` 的 `tgid` 读取
- `tid` 从传入 `task` 的 `pid` 读取

注意：

- `pid/tid` 长时间运行时可能复用
- 建议最终输出中始终带 `timestamp_ns`
- 如后续需要增强唯一性，可以增加 `start_time` 或 task start boottime，但这不属于 v1 必选字段

### 6.2 comm

字段：

- `comm`

语义：

- 当前任务名

实现来源：

- 传入 `task->comm`

### 6.3 scontext

字段：

- `scontext`

语义：

- SELinux 主体上下文

实现来源：

1. 先从传入 `cred` 取主体 secid/sid
2. 再调用 secid/sid 转 context 的接口得到 context string

建议内部同时保留 subject sid，便于调试和后续扩展，但 v1 JSON 可以只输出 `scontext`

### 6.4 关于 current 语义

这里的 `subject` 语义是：

- 外部在 hook 现场抓到并稳定保存下来的 `task/cred`

这比“resolver 异步运行时再读取当前 `current`”更准确，因为异步阶段的 `current` 可能已经变成 worker 线程自己。

## 7. request 字段定义

`request` 表示这次访问请求本身。

### 7.1 mask_raw

字段：

- `mask_raw`

语义：

- hook 原始 mask

来源：

- `inode_permission.mask`
- `file_permission.mask`
- `file_open` 没有单独 `mask` 参数，v1 约定输出 `0`

### 7.2 obj_type

字段：

- `obj_type`

语义：

- 由 `inode->i_mode` 解码出的对象类型

典型取值：

- `reg`
- `dir`
- `lnk`
- `chr`
- `blk`
- `fifo`
- `sock`
- `unknown`

实现来源：

- 从目标 `inode->i_mode` 解码

### 7.3 perm

字段：

- `perm`

语义：

- 结合对象类型和原始请求解码后的最终权限语义
- 如果有多个权限，用 `|` 拼接

典型取值：

- `read`
- `write`
- `append`
- `exec`
- `search`
- `open|read`
- `open|append`

### 7.4 perm 解码规则

v1 只考虑 SELinux 文件相关语义里常见的：

- `MAY_READ`
- `MAY_WRITE`
- `MAY_EXEC`
- `MAY_APPEND`

建议规则：

- 对普通文件：
  - `MAY_READ` -> `read`
  - `MAY_WRITE` -> `write`
  - `MAY_APPEND` -> `append`
  - `MAY_EXEC` -> `exec`
- 对目录：
  - `MAY_READ` -> `read`
  - `MAY_WRITE` -> `write`
  - `MAY_EXEC` -> `search`

补充规则：

- `file_open` 额外带上 `open`
- 如果 `file->f_flags` 含 `O_APPEND`，并且语义是写，则优先解释为 `append`

## 8. target 字段定义

`target` 从文件系统视角和 SELinux 视角共同描述访问目标。

### 8.1 dev

字段：

- `dev`

语义：

- 对象所在文件系统标识

实现来源：

- `inode->i_sb->s_id`

### 8.2 ino

字段：

- `ino`

语义：

- inode 号

实现来源：

- `inode->i_ino`

### 8.3 type

字段：

- `type`

语义：

- 文件系统对象类型

实现来源：

- `inode->i_mode`

典型取值与 `obj_type` 一致：

- `reg`
- `dir`
- `lnk`
- `chr`
- `blk`
- `fifo`
- `sock`

### 8.4 path

字段：

- `path`

语义：

- 这次访问对应的路径表示

实现要求：

- 优先输出绝对路径
- 如果拿不到绝对路径，至少输出文件名或 alias name

实现说明：

- 这是 v1 里最复杂的字段之一
- 对 `file *`，优先尝试从 `file` 对应路径恢复
- 对只有 `inode *` 的场景，路径恢复可能不稳定，允许 best effort
- 如果无法保证绝对路径，就退而求其次输出 basename 或可识别名称

因此 v1 对 `path` 的要求是：

- 尽力获取绝对路径
- 实在不行，至少给出文件名

### 8.5 tclass

字段：

- `tclass`

语义：

- 目标对象的 SELinux 类别，例如 `file`、`dir`

实现来源：

1. 先取 `selinux_inode(inode)`
2. 再读取 `isec->sclass`

### 8.6 tcontext

字段：

- `tcontext`

语义：

- 目标对象的 SELinux 安全上下文

实现来源：

1. 先取 `selinux_inode(inode)`
2. 再读取 `isec->sid`
3. 调用 `security_sid_to_context()` 转成 context string

和 `scontext` 一样，内部建议同时保留 `sid`，但 v1 JSON 可以先只输出字符串形式

## 9. result 字段定义

### 9.1 ret

字段：

- `ret`

语义：

- hook 最终返回值

来源：

- 外部直接提供

### 9.2 runtime_result

字段：

- `runtime_result`

语义：

- `ret` 在运行时上的直接含义

取值约定：

- `allow`
- `deny`
- `error`

判定规则：

- `ret == 0` -> `allow`
- `ret == -EACCES` -> `deny`
- 其他负值 -> `error`

如果你后续希望把 `-EPERM` 也并入 `deny`，可以在实现时作为可配置项处理，但当前 v1 先按你提供的口径写成 `-EACCES` 明确表示 SELinux deny。

### 9.3 policy_result

字段：

- `policy_result`

语义：

- 从 SELinux 策略角度看，这次请求是否被允许

问题背景：

- `ret` 不能直接代表 SELinux policy 结果
- 因为：
  - 策略不允许 + enforcing -> `ret < 0`
  - 策略不允许 + permissive -> `ret == 0`

因此 `policy_result` 不能简单等同于 `runtime_result`

### 9.4 policy_result 的 v1 约定

目前该字段的获取方式还未最终定稿，因此 v1 文档只约定语义，不强行规定唯一实现路径。

v1 推荐输出值：

- `allow`
- `deny`
- `unknown`

建议：

- 如果后续能通过 SELinux/AVC 路径得到真实策略结论，则填 `allow` 或 `deny`
- 如果当前版本还没有稳定方案，则填 `unknown`

也就是说：

- `ret` 是必选
- `runtime_result` 是必选
- `policy_result` 是语义上保留、实现上允许暂时 `unknown`

## 10. 不同 hook 的解析方式

### 10.1 selinux_inode_permission

输入：

- `struct inode *inode`
- `int mask`
- `int ret`

解析要点：

- `subject` 从 `current` 获取
- `request.mask_raw = mask`
- `request.obj_type` 从 `inode->i_mode` 解码
- `request.perm` 根据 `mask + inode->i_mode` 解码
- `target` 全部从 `inode` 和 `selinux_inode(inode)` 获取

### 10.2 selinux_file_open

输入：

- `struct file *file`
- `int ret`

解析要点：

- `subject` 从 `current` 获取
- `target` 需要先从 `file` 找到对应 `inode`
- `request.mask_raw = 0`
- `request.perm` 根据 `file` 打开语义解码，一般包含 `open`
- 路径优先从 `file` 关联路径恢复

### 10.3 selinux_file_permission

输入：

- `struct file *file`
- `int mask`
- `int ret`

解析要点：

- `subject` 从 `current` 获取
- `target` 需要从 `file` 找到对应 `inode`
- `request.mask_raw = mask`
- `request.perm` 根据 `mask + inode->i_mode + file->f_flags` 解码
- 如果带 `O_APPEND`，写语义优先转成 `append`

## 11. 推荐的内部数据结构

建议统一输出结构如下：

```c
struct lha_subject_v1 {
    __u32 pid;
    __u32 tid;
    char scontext[256];
    char comm[TASK_COMM_LEN];
};

struct lha_request_v1 {
    __s32 mask_raw;
    char obj_type[32];
    char perm[64];
};

struct lha_target_v1 {
    char dev[32];
    __u64 ino;
    char type[32];
    char path[512];
    char tclass[32];
    char tcontext[256];
};

struct lha_result_v1 {
    __s32 ret;
    char runtime_result[16];
    char policy_result[16];
};

struct lha_enriched_event_v1 {
    __u16 version;
    __u16 hook_id;
    __u64 timestamp_ns;
    char hook[64];
    char hook_signature[128];

    struct lha_subject_v1 subject;
    struct lha_request_v1 request;
    struct lha_target_v1 target;
    struct lha_result_v1 result;
};
```

## 12. 推荐 JSON 输出

最终建议输出如下 JSON 结构：

```json
{
  "hook": "selinux_file_permission",
  "hook_signature": "static int selinux_file_permission(struct file *file, int mask)",
  "timestamp_ns": 1710000000000000000,
  "subject": {
    "pid": 1234,
    "tid": 1234,
    "scontext": "u:r:untrusted_app:s0:c123,c456",
    "comm": "app_process"
  },
  "request": {
    "mask_raw": 2,
    "obj_type": "reg",
    "perm": "append"
  },
  "target": {
    "dev": "dm-3",
    "ino": 1234567,
    "type": "reg",
    "path": "/data/local/tmp/a.log",
    "tclass": "file",
    "tcontext": "u:object_r:shell_data_file:s0"
  },
  "result": {
    "ret": -13,
    "runtime_result": "deny",
    "policy_result": "unknown"
  }
}
```

## 13. v1 明确不做的事情

v1 不做以下事情：

- 用户态 mock `current`
- 用户态回读 `/proc/self/attr/current` 伪装成 hook 现场主体
- 用户态 `getxattr()` 伪装成目标对象 hook 现场 SELinux 状态
- 为了“看起来完整”而伪造 context
- 在文档里强行承诺 `policy_result` 一定能得到

## 14. 当前实现建议

v1 最推荐的实现顺序：

1. 先把输入结构和路由入口定下来
2. 实现 `subject` 解析：
   - `current`
   - `pid/tid`
   - `comm`
   - `cred_sid(current_cred())`
   - `security_sid_to_context()`
3. 实现 `inode` / `file` 到 `target` 的解析
4. 实现 `mask` 到 `perm` 的解码
5. 实现 JSON 序列化
6. 最后再补 `policy_result`

## 15. 当前待定点

现在只剩一个核心未定点：

- `policy_result` 的真实获取方式

除此之外，其余字段的来源、含义、hook 路由方式和输出格式，在本文档中已经固定为 v1 方案。
