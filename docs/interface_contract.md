# 接口约束

本文档只描述当前 `kmod/lha_centos9_resolver.h` 中已经定义并在 `kmod/` 实现里真正使用的接口约束。

## 1. 支持的 hook 类型

`hook_id` 当前只能取以下 3 个值：

```c
enum lha_hook_id {
	LHA_HOOK_INODE_PERMISSION = 1,
	LHA_HOOK_FILE_OPEN = 2,
	LHA_HOOK_FILE_PERMISSION = 3,
};
```

分别对应：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

传入其他值时，`lha_centos9_resolve_event()` 会返回 `-EINVAL`。

## 2. 输入结构

当前输入结构为：

```c
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

### 2.1 必填字段

- `version`
  当前必须填 `1`
- `hook_id`
  必须是 3 个受支持值之一
- `ts_ns`
  事件时间戳
- `ret`
  hook 最终返回值
- `subject.task`
  hook 现场保存的稳定 `task_struct` 引用
- `subject.cred`
  hook 现场保存的稳定 `cred` 引用

### 2.2 按 hook 类型填写的参数

- `LHA_HOOK_INODE_PERMISSION`
  需要填写 `args.inode_permission.inode` 和 `args.inode_permission.mask`
- `LHA_HOOK_FILE_OPEN`
  需要填写 `args.file_open.file`
- `LHA_HOOK_FILE_PERMISSION`
  需要填写 `args.file_permission.file` 和 `args.file_permission.mask`

## 3. 输出结构

当前输出结构为：

```c
struct lha_enriched_event_v1 {
	__u16 version;
	__u16 hook_id;
	__u64 timestamp_ns;
	char hook[LHA_MAX_HOOK_LEN];
	char hook_signature[LHA_MAX_SIG_LEN];
	struct lha_subject_v1 subject;
	struct lha_request_v1 request;
	struct lha_target_v1 target;
	struct lha_result_v1 result;
};
```

输出字段分为 4 组：

- `subject`
  主体信息
- `request`
  请求信息
- `target`
  目标对象信息
- `result`
  结果信息

## 4. 字段语义

### 4.1 `subject`

```c
struct lha_subject_v1 {
	__u32 pid;
	__u32 tid;
	char scontext[LHA_MAX_CONTEXT_LEN];
	char comm[LHA_MAX_COMM_LEN];
};
```

实际来源：

- `pid`
  `task_tgid_nr(task)`
- `tid`
  `task_pid_nr(task)`
- `comm`
  `task->comm`
- `scontext`
  `security_cred_getsecid()` + `security_secid_to_secctx()`

### 4.2 `request`

```c
struct lha_request_v1 {
	__s32 mask_raw;
	char obj_type[LHA_MAX_TYPE_LEN];
	char perm[LHA_MAX_PERM_LEN];
};
```

当前实现中的语义：

- `mask_raw`
  - `inode_permission` 和 `file_permission` 输出原始 `mask`
  - `file_open` 输出 `0`
- `obj_type`
  由 `inode->i_mode` 解码，当前可能值为：
  `reg`、`dir`、`lnk`、`chr`、`blk`、`fifo`、`sock`、`unknown`
- `perm`
  当前可能值由以下 token 组合而成：
  `open`、`read`、`write`、`append`、`exec`、`search`

### 4.3 `target`

```c
struct lha_target_v1 {
	char dev[LHA_MAX_DEV_LEN];
	__u64 ino;
	char type[LHA_MAX_TYPE_LEN];
	char path[LHA_MAX_PATH_LEN];
	char tclass[LHA_MAX_TYPE_LEN];
	char tcontext[LHA_MAX_CONTEXT_LEN];
};
```

当前实现中的语义：

- `dev`
  取 `inode->i_sb->s_id`
- `ino`
  取 `inode->i_ino`
- `type`
  与 `request.obj_type` 使用同一组对象类型字符串
- `path`
  路径恢复结果；失败时会退化成 dentry 名称或 `<unknown>`
- `tclass`
  当前可能值为：
  `file`、`dir`、`lnk_file`、`chr_file`、`blk_file`、`fifo_file`、`sock_file`、`unknown`
- `tcontext`
  `security_inode_getsecctx()` 返回的 SELinux 目标上下文

### 4.4 `result`

```c
struct lha_result_v1 {
	__s32 ret;
	char runtime_result[LHA_MAX_RESULT_LEN];
	char policy_result[LHA_MAX_RESULT_LEN];
};
```

当前实现中的语义：

- `ret`
  原样复制输入返回值
- `runtime_result`
  - `ret == 0` -> `allow`
  - `ret == -EACCES` -> `deny`
  - 其他值 -> `error`
- `policy_result`
  当前主解析路径实际只会输出：
  - `deny`
  - `inferred_allow`
  - `unknown`

## 5. JSON 输出结构

`lha_centos9_format_json()` 会输出以下固定顶层字段：

- `hook`
- `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

当前实现不会输出额外的可选字段，也不会按不同 hook 类型裁剪字段集合。

## 6. 返回值约束

### 6.1 `lha_centos9_resolve_event()`

成功返回 `0`。

当前常见失败场景会返回负错误码，最常见的是 `-EINVAL`，包括：

- `in` 或 `out` 为空
- `version != 1`
- `subject.task` 或 `subject.cred` 为空
- `hook_id` 无效
- 主体或目标解析失败

### 6.2 `lha_centos9_format_json()`

当前实现的行为是：

- `event == NULL`、`buf == NULL` 或 `buf_len == 0` -> `-EINVAL`
- 其他有效输入 -> 当前实现返回 `0`

调用方需要自己保证缓冲区足够大，因为当前实现不会把截断当成错误返回。

### 6.3 `lha_centos9_record_avc_event()`

只有在以下条件同时满足时才会接受输入：

- `event` 非空
- `event->denied != 0`
- `scontext`、`tcontext`、`tclass`、`perm` 非空字符串

否则返回 `-EINVAL`。

## 7. 执行上下文约束

resolver 设计为在可睡眠上下文中运行。当前实现会调用：

- `security_secid_to_secctx()`
- `security_inode_getsecctx()`
- `d_path()`
- `kmalloc(GFP_KERNEL)`

因此不应把 `lha_centos9_resolve_event()` 直接放进不可睡眠上下文。

## 8. 引用生命周期约束

resolver 不负责替调用方建立或释放输入对象引用。外部模块必须在 hook 现场建立稳定引用，并在解析完成后自行释放。

典型对应关系：

- `task` -> `get_task_struct()` / `put_task_struct()`
- `cred` -> `get_cred()` / `put_cred()`
- `inode` -> `igrab()` 或 `ihold()` / `iput()`
- `file` -> `get_file()` / `fput()`
