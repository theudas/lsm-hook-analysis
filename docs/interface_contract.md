# LSM Hook Analysis 接口文档

## 1. 文档目的

本文档定义 `lsm-hook-analysis` 项目的接口边界、数据契约和实现约束。

该项目的目标不是做一个“语义近似的用户态 demo”，而是基于外部已经抓取到的 **LSM hook 参数与返回值**，补齐其余分析字段，并输出一份可用于审计、策略分析或后续消费的结构化事件。

本文档默认以下约束成立：

- LSM hook 的参数和返回值由外部模块负责抓取。
- 本项目只消费外部抓取结果，不负责 hook 注册与原始抓取。
- 除“hook 参数和返回值”这部分外，其余字段不得使用 mock 数据伪造。
- 如果某字段无法从真实内核态上下文可靠获得，则必须明确标记为 `unavailable` / `unknown`，不能 silently fallback 成伪造值。

## 2. 核心设计原则

### 2.1 允许外部输入的范围

本项目唯一允许直接信任的外部输入为：

- hook 类型
- hook 参数
- hook 返回值
- 与 hook 现场强绑定、且由抓取方保证稳定性的对象引用

### 2.2 禁止的实现方式

以下方式不满足本项目目标：

- 使用用户态 `getpid()`、`/proc/self/comm`、`/proc/self/attr/current` 代替 hook 触发当时的 `current`
- 使用用户态 `getxattr()` 在事后补读目标对象标签，并声称等价于 hook 当时的真实内核对象状态
- 在读取失败时自动生成 `mock_u:mock_r:xxx_t:s0` 这类伪造上下文
- 仅凭路径字符串事后重建 `inode` / `file` / `cred` 相关信息

### 2.3 必须承认的技术边界

如果外部抓取方只提供了“纯值类型参数”和返回值，例如：

- `mask`
- `ret`
- `path`
- `comm`

而没有提供与 hook 现场绑定的内核对象引用，或者没有在 hook 上下文内同步完成解析，那么本项目 **无法真实恢复** 以下信息：

- 触发该次 hook 的真实 `current`
- `current->cred` / SELinux subject context
- `inode->i_security` / `file->f_security`
- hook 触发瞬间的对象安全标签

因此，接口设计必须把“如何获得真实 `current` 及其关联对象”作为硬性前提写入契约。

## 3. 总体链路

推荐链路如下：

1. 外部 hook 抓取模块在 hook 现场抓取原始参数、返回值，以及最小必要对象引用。
2. 本项目的 enrich/resolver 模块在仍可访问真实内核对象的前提下，读取 `current`、`cred`、目标对象与 SELinux 安全属性。
3. 本项目生成统一的结构化事件。
4. 结构化事件交由用户态、日志管道或其他消费者继续处理。

## 4. 组件边界

本项目内部逻辑拆分为两个接口层：

- `Capture Input Interface`
  由外部 hook 抓取方传入本项目的原始输入
- `Enriched Output Interface`
  由本项目产出的统一结构化事件

必要时，可增加一个内部接口：

- `Kernel Resolver Interface`
  由本项目内部实现，用于基于真实内核对象补齐字段

## 5. Capture Input Interface

### 5.1 设计目标

该接口描述“外部抓取方最少必须提供什么”，才能让本项目有能力产出真实 enriched event。

### 5.2 输入对象定义

建议定义统一输入结构 `lha_capture_event_v1`。

示意字段如下：

```c
enum lha_hook_id {
    LHA_HOOK_INODE_PERMISSION = 1,
    LHA_HOOK_FILE_OPEN = 2,
    LHA_HOOK_FILE_PERMISSION = 3,
};

struct lha_obj_ref {
    const void *ptr;
    __u64 id;
};

struct lha_capture_event_v1 {
    __u16 version;
    __u16 hook_id;
    __u32 cpu;
    __u64 seq;
    __u64 ts_ns;

    __s32 ret;

    union {
        struct {
            struct lha_obj_ref inode;
            __s32 mask;
        } inode_permission;

        struct {
            struct lha_obj_ref file;
        } file_open;

        struct {
            struct lha_obj_ref file;
            __s32 mask;
        } file_permission;
    } args;

    struct {
        const void *current_task;
        const void *current_cred;
    } subject_ref;
};
```

### 5.3 字段要求

以下字段为必选：

- `version`
- `hook_id`
- `ts_ns`
- `ret`
- hook 对应参数

以下字段为强烈建议设为必选：

- `subject_ref.current_task`
- `subject_ref.current_cred`

原因：

- 如果本项目的 enrich 逻辑不是直接运行在 hook 回调现场，那么没有这两个引用就无法确认“要解析的是哪个 task/cred”。
- 即使提供了这两个指针，也仍需上游保证引用在 resolver 使用阶段有效，或者由 resolver 在 hook 现场同步读取并复制稳定字段。

### 5.4 关于对象引用的要求

`inode` / `file` / `current_task` / `current_cred` 推荐传递：

- 内核地址指针，供内核态 resolver 直接读取
- 或者由外部抓取方在 hook 现场建立的稳定对象句柄

不能只传：

- 路径字符串
- inode 号
- pid/tid

这些值只能用于辅助索引，不能保证等价于 hook 当时的真实对象。

## 6. Kernel Resolver Interface

### 6.1 作用

该接口是本项目内部接口，用于从真实内核对象中提取 subject、target、SELinux 相关字段。

### 6.2 推荐函数形式

```c
int lha_resolve_event(const struct lha_capture_event_v1 *in,
                      struct lha_enriched_event_v1 *out);
```

### 6.3 输入前提

`lha_resolve_event()` 成功工作的前提至少满足其一：

1. 它运行在 hook 回调现场，可直接访问真实 `current` 和 hook 参数对象。
2. 上游传入的对象引用在 resolver 执行时仍然有效，且生命周期已被正确保护。

如果两者都不满足，则 resolver 必须返回失败，而不是用 mock 数据顶替。

### 6.4 resolver 需要补齐的真实字段

#### subject 侧

- `task_struct` 对应的 `pid/tgid`
- 线程名 `comm`
- `current->cred`
- SELinux subject SID / 安全上下文

#### target 侧

按 hook 类型从真实对象取值：

- `inode_permission`
  从 `struct inode *` 提取 inode 元数据与安全属性
- `file_open`
  从 `struct file *` 提取 `f_flags`、`f_mode`、`f_inode`
- `file_permission`
  从 `struct file *` 和 `mask` 提取权限语义与目标对象信息

#### SELinux 侧

在 SELinux 启用场景下，优先读取真实内核安全对象，而不是用户态回读：

- subject SID / context
- target SID / context
- target class

若当前内核配置、LSM 栈或对象类型不支持直接解析 context 字符串，可输出：

- SID
- class
- `context_resolved = false`

但不能捏造 context 文本。

## 7. Enriched Output Interface

### 7.1 输出目标

本项目统一输出 `lha_enriched_event_v1`，用于后续序列化、日志写出或用户态消费。

### 7.2 输出结构建议

```c
enum lha_field_state {
    LHA_FIELD_OK = 0,
    LHA_FIELD_UNAVAILABLE = 1,
    LHA_FIELD_UNRESOLVED = 2,
};

struct lha_subject_info_v1 {
    __u32 pid;
    __u32 tgid;
    __u64 task_ptr;
    __u64 cred_ptr;
    char comm[16];

    __u32 sid;
    char scontext[256];
    __u8 scontext_state;
};

struct lha_request_info_v1 {
    __s32 mask_raw;
    char perm[64];
    char obj_type[32];
};

struct lha_target_info_v1 {
    __u64 inode_ptr;
    __u64 file_ptr;
    __u64 ino;
    __u32 mode;
    __u64 dev;
    char path[512];
    __u8 path_state;

    __u32 sid;
    char tcontext[256];
    __u8 tcontext_state;

    char tclass[32];
    char type[32];
};

struct lha_result_info_v1 {
    __s32 ret;
    char runtime_result[16];
    char policy_result[16];
};

struct lha_enriched_event_v1 {
    __u16 version;
    __u16 hook_id;
    __u64 seq;
    __u64 ts_ns;

    struct lha_subject_info_v1 subject;
    struct lha_request_info_v1 request;
    struct lha_target_info_v1 target;
    struct lha_result_info_v1 result;
};
```

### 7.3 输出字段语义

#### subject

- `pid` / `tgid`
  来自真实 `task_struct`
- `task_ptr` / `cred_ptr`
  用于调试、溯源和校验
- `comm`
  来自真实 task
- `sid` / `scontext`
  来自真实 subject security state

#### request

- `mask_raw`
  保留原始 hook 参数
- `perm`
  由 resolver 按 hook 语义解释
- `obj_type`
  由真实目标对象类型推导

#### target

- `inode_ptr` / `file_ptr`
  记录解析来源
- `ino` / `mode` / `dev`
  来自真实 inode / file
- `path`
  可选字段，只能在可靠拿到路径时填写
- `sid` / `tcontext` / `tclass`
  来自真实 target security state

#### result

- `ret`
  原始返回值
- `runtime_result`
  运行时结果分类，例如 `allow` / `deny` / `error`
- `policy_result`
  若可以从 hook 语义或外部策略判定中得出，则填写；否则写 `unknown`

## 8. 字段状态约定

为了避免“看起来有值，但其实是猜的”，所有可能缺失的字段都应显式带状态。

推荐规则：

- `LHA_FIELD_OK`
  成功从真实来源解析
- `LHA_FIELD_UNAVAILABLE`
  该字段当前场景客观不可获取
- `LHA_FIELD_UNRESOLVED`
  理论上可获取，但本次解析失败

例如：

- `scontext_state = LHA_FIELD_UNAVAILABLE`
  表示当前环境不提供 context 字符串解析能力
- `path_state = LHA_FIELD_UNRESOLVED`
  表示本次未能可靠恢复路径

## 9. 关于 current 的硬性要求

这是本项目最关键的接口约束。

如果目标是“读取 hook 触发当时的真实 `current`”，则必须满足以下至少一项：

1. enrich/resolver 与 hook 抓取运行在同一内核执行路径中。
2. hook 抓取方将 `current` 的稳定引用显式传给 resolver，并确保对象生命周期安全。

以下做法均不满足要求：

- 在用户态收到事件后，用“当前进程自己”代替 hook 触发进程
- 在用户态通过 pid 反查并假设等价于当时的 `current`
- 用 `/proc/<pid>` 的后验状态补写 hook 现场状态

换句话说：

**只要你需要“真实 current”，解析动作就必须和 hook 现场共享真实内核对象语义。**

## 10. 关于路径字段的约束

路径不是所有 hook 都天然可靠拥有的字段。

因此：

- `path` 必须定义为可选
- 如果路径恢复依赖 dentry/path walk，必须明确该路径是否为 hook 触发瞬间可见路径
- 如果只能得到对象标识而不能可靠恢复路径，则输出空值并设置 `path_state`

不能把路径当成 target 身份的唯一依据。

## 11. 错误处理约定

resolver 应返回明确错误码，而不是隐式降级。

建议错误分类：

- `-EINVAL`
  输入结构不合法
- `-EOPNOTSUPP`
  当前 hook 或当前 LSM/内核配置不支持所需解析
- `-ENOENT`
  目标对象已不可用
- `-ESTALE`
  上游传入对象引用已失效
- `-EFAULT`
  读取对象字段失败

发生错误时：

- 已成功解析的字段可以保留
- 未成功解析的字段必须显式标记状态
- 不能自动填充 mock 字段

## 12. 版本兼容

所有输入输出结构必须带 `version` 字段。

推荐策略：

- `v1`
  固定三类 hook：`inode_permission`、`file_open`、`file_permission`
- 新增 hook 时优先扩展 `hook_id + union args`
- 字段语义变化时升级主版本

## 13. v1 必须支持的 hook

第一阶段建议只定义以下三类：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

每类 hook 都必须满足：

- 保留原始参数
- 能解析 request 语义
- 能关联真实 subject
- 能输出真实 target 安全信息

## 14. 非目标

以下内容不属于当前文档要求的 v1 范围：

- 用户态 demo 程序
- 用 mock 结构体伪装内核对象
- 为了“看起来完整”而补 fake SELinux context
- 跨所有 LSM 的统一抽象
- 完整策略判定引擎

## 15. 建议的后续实现顺序

1. 先把 `Capture Input Interface` 定死，尤其是对象引用和生命周期约束。
2. 实现仅在内核态运行的 `resolver` 原型。
3. 先支持 `inode_permission`、`file_open`、`file_permission` 三个 hook。
4. 最后再补序列化层，例如 JSON 输出或 ringbuf/event export。

## 16. 当前待确认问题

在进入代码实现前，建议先确认以下问题：

1. 外部抓取方是否能传入 `current_task` / `current_cred` / `inode` / `file` 的稳定引用？
2. resolver 是在 hook 现场同步运行，还是在事件队列中异步运行？
3. 目标环境是否要求输出 SELinux context 字符串，还是 SID 即可？
4. 路径字段是否是强需求，还是可选调试字段？

如果上述问题未定，后续代码实现很容易在“真实可实现”和“事后猜测”之间混淆。
