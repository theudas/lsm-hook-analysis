# `lha_centos9_resolver.ko` 模块说明

## 1. 模块职责

`lha_centos9_resolver.ko` 是项目的核心模块，负责把外部抓取模块提交的原始 SELinux hook 事件解析成统一的结构化结果，并按需格式化为 JSON。

它当前只支持以下 3 类 hook 输入：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

resolver 自己不负责注册或抓取这些 hook。真实生产链路里，hook 参数和返回值必须由外部模块采集后再交给它处理。

## 2. 对外接口

头文件：`kmod/lha_centos9_resolver.h`

当前导出的 GPL 符号如下：

- `lha_centos9_resolve_event()`
- `lha_centos9_format_json()`
- `lha_centos9_record_avc_event()`
- `lha_centos9_policy_result_kind_to_string()`
- `lha_centos9_correlate_avc_policy()`
- `lha_centos9_apply_avc_policy_result()`

其中生产链路最常用的是前 3 个：

- `lha_centos9_resolve_event()`
  解析单条 `struct lha_capture_event_v1`
- `lha_centos9_format_json()`
  把 `struct lha_enriched_event_v1` 格式化成 JSON
- `lha_centos9_record_avc_event()`
  向 resolver 内部 AVC 缓存写入一条 deny 事件

## 2.1 调试开关

当前模块提供一个可动态修改的调试参数：

- `debug_avc_cache`

开启后会额外打印：

- AVC 事件被拒绝入缓存的原因
- AVC 事件成功写入环形缓存时的下标和关键字段

加载时开启：

```bash
sudo insmod lha_centos9_resolver.ko debug_avc_cache=1
```

模块已加载后在线开启：

```bash
echo 1 | sudo tee /sys/module/lha_centos9_resolver/parameters/debug_avc_cache
```

## 3. 输入与输出

输入结构是 `struct lha_capture_event_v1`，关键字段包括：

- `version`
  当前必须为 `1`
- `hook_id`
  指定 3 类 hook 中的哪一种
- `ts_ns`
  原始事件时间戳
- `ret`
  hook 最终返回值
- `subject.task`
  hook 现场保存的稳定 `task_struct` 引用
- `subject.cred`
  hook 现场保存的稳定 `cred` 引用
- `args.*`
  hook 原始参数

输出结构是 `struct lha_enriched_event_v1`，包含：

- `hook`、`hook_signature`
- `subject`
- `request`
- `target`
- `result`

## 4. 解析流程

`lha_centos9_resolve_event()` 的实际处理顺序是：

1. 校验 `in/out` 非空、`version == 1`、`subject.task/cred` 非空。
2. 按 `hook_id` 路由到 3 个解析函数之一。
3. 从传入的 `task` 读取 `pid`、`tid`、`comm`。
4. 从传入的 `cred` 读取主体 secid，再调用 `security_secid_to_secctx()` 转成 `scontext`。
5. 从 `inode` 或 `file` 读取目标对象的 `dev`、`ino`、`type`、`tclass`、`tcontext`、`path`。
6. 解码 `mask` 或 `file->f_flags`，生成 `request.perm`。
7. 根据 `ret` 生成 `runtime_result`。
8. 使用 resolver 内部 AVC 缓存重新计算 `policy_result`。

当前实现里，`policy_result` 在进入 AVC 关联前会先初始化成 `unknown`，随后再由 resolver 内部 AVC 缓存关联逻辑更新。

## 5. 各字段如何生成

### 5.1 `subject`

- `pid`
  取 `task_tgid_nr(task)`
- `tid`
  取 `task_pid_nr(task)`
- `comm`
  取 `task->comm`
- `scontext`
  取 `security_cred_getsecid()` + `security_secid_to_secctx()` 的结果

### 5.2 `target`

- `dev`
  取 `inode->i_sb->s_id`
- `ino`
  取 `inode->i_ino`
- `type`
  由 `inode->i_mode` 解码成 `reg/dir/lnk/chr/blk/fifo/sock/unknown`
- `tclass`
  由 `inode->i_mode` 解码成 `file/dir/lnk_file/chr_file/blk_file/fifo_file/sock_file/unknown`
- `tcontext`
  取 `security_inode_getsecctx()` 的结果
- `path`
  `file *` 走 `d_path()`，`inode *` 走 `d_find_alias()` + `dentry_path_raw()`

路径恢复是 best effort：

- `file *` 一般更容易拿到接近用户态视角的完整路径
- `inode *` 因为没有 mount/path 上下文，不保证拿到全局绝对路径
- 路径恢复失败时，resolver 仍可能成功返回，但 `path` 会退化成 dentry 名称或 `<unknown>`

### 5.3 `request`

- `mask_raw`
  对 `inode_permission` 和 `file_permission` 直接输出原始 `mask`
- `file_open`
  当前固定输出 `0`

- `obj_type`
  由 `inode->i_mode` 解码

- `perm`
  当前实现只输出以下语义组合：
  `open`、`read`、`write`、`append`、`exec`、`search`

权限解码规则：

- `inode_permission`
  由传入 `mask` 解码；目录上的执行权限会映射成 `search`
- `file_open`
  由 `file->f_flags` 解码；当前总会带 `open`
- `file_permission`
  由传入 `mask` 解码；若 `file->f_flags` 带 `O_APPEND` 且请求带 `MAY_WRITE`，会优先输出 `append`

### 5.4 `result`

- `ret`
  直接输出输入值
- `runtime_result`
  只按以下规则分类：
  - `ret == 0` -> `allow`
  - `ret == -EACCES` -> `deny`
  - 其他返回值 -> `error`
- `policy_result`
  由内置 AVC 缓存关联逻辑生成，当前主路径实际只会得到：
  - `deny`
  - `inferred_allow`
  - `unknown`

## 6. AVC 关联逻辑

resolver 内部维护了一个固定长度的 AVC 环形缓存：

- 容量：`128`
- 默认关联时间窗：`50 ms`

缓存只接受 `denied != 0` 且匹配字段完整的 AVC 事件。匹配键包括：

- `scontext`
- `tcontext`
- `tclass`
- `perm`

若 AVC 事件还带有 `tid`、`pid`、`comm`，resolver 会进一步用这些字段打分，以减少误配。

关联结果规则：

- 找到唯一最佳匹配 -> `deny`
- 没有匹配到 deny -> `inferred_allow`
- 缺少关键匹配键，或出现同分同时间差的歧义 -> `unknown`

当前实现不会基于 AVC 关联生成强语义的 `allow`。

## 7. 执行上下文要求

该模块设计为运行在可睡眠上下文中，例如：

- `workqueue`
- `kthread`

不建议在原始 hook 回调中直接调用。当前实现依赖以下可能睡眠的操作：

- `security_secid_to_secctx()`
- `security_inode_getsecctx()`
- `d_path()`
- `kmalloc(GFP_KERNEL)`

## 8. 失败场景

`lha_centos9_resolve_event()` 当前在以下情况下会返回 `-EINVAL`：

- 输入或输出指针为空
- `version != 1`
- `subject.task` 或 `subject.cred` 为空
- `hook_id` 不是 3 个受支持值之一
- 主体或目标对象解析失败

需要注意两类边界：

- 路径恢复失败通常不会导致整个解析失败，resolver 会尽量回退到名称或 `<unknown>`
- `security_inode_getsecctx()` 或 `security_secid_to_secctx()` 失败会导致整个解析失败

## 9. JSON 输出边界

`lha_centos9_format_json()` 会把事件组织成一个固定字段集合的 JSON 对象。当前实现对参数校验较严格，但对“缓冲区是否足够”没有单独返回截断错误。

实际含义是：

- `event == NULL`、`buf == NULL`、`buf_len == 0` 时返回 `-EINVAL`
- 其他情况下当前实现返回 `0`
- 如果缓冲区太小，输出会被 `vscnprintf()` 截断，因此调用方应主动提供足够大的缓冲区

仓库内的 injector 使用 `8192` 字节缓冲区，可作为参考。

## 10. 适用场景与限制

适合：

- 生产链路里的 hook 后置解析
- 外部抓取模块统一输出 JSON 或结构化结果
- 结合 AVC deny 进行基础策略结果判断

不适合：

- 直接作为 hook 抓取模块使用
- 直接给出强语义的 SELinux `allow`
- 脱离稳定对象引用的异步解析
