# `lha_centos9_avc_capture.ko` 模块说明

## 1. 模块职责

`lha_centos9_avc_capture.ko` 是 resolver 的可选增强模块，用来采集 SELinux AVC deny 事件，并把它们写入 resolver 内部缓存，供后续 hook 解析结果做 `policy_result` 关联。

它不输出最终 JSON，也不直接解析 hook 输入。它只做两件事：

- 订阅内核里的 SELinux 审计 tracepoint
- 把观测到的 deny 事件归一化成 `struct lha_avc_event_v1`

## 2. 依赖关系

该模块依赖 `lha_centos9_resolver.ko` 提供的：

- `lha_centos9_record_avc_event()`

模块里通过 `MODULE_SOFTDEP("pre: lha_centos9_resolver")` 声明了这一点，但实际加载时仍建议显式先加载 resolver。

## 3. 依赖的内核能力

当前实现要求目标内核提供：

- 名为 `selinux_audited` 的 tracepoint
- `for_each_kernel_tracepoint()`
- `tracepoint_probe_register()` / `tracepoint_probe_unregister()`

仓库附带的 `centos-stream-9/` 内核树中可以找到：

- `include/trace/events/avc.h`
  定义 `TRACE_EVENT(selinux_audited, ...)`
- `security/selinux/avc.c`
  调用 `trace_selinux_audited(...)`

因此这份实现是按 CentOS Stream 9 的 SELinux AVC tracepoint 形态编写的。

## 4. 启动流程

模块加载时会：

1. 调用 `for_each_kernel_tracepoint()` 遍历所有内核 tracepoint。
2. 找到名为 `selinux_audited` 的 tracepoint。
3. 通过 `tracepoint_probe_register()` 注册 `lha_avc_trace_probe()`。

如果找不到该 tracepoint，模块初始化会失败并返回 `-ENOENT`。

## 5. 调试开关

当前模块提供一个可动态修改的调试参数：

- `debug_capture`

它开启后会额外打印：

- probe 是否抓到了一条真实 AVC deny
- 这条事件是否成功转发给 resolver

加载时开启：

```bash
sudo insmod lha_centos9_avc_capture.ko debug_capture=1
```

模块已加载后在线开启：

```bash
echo 1 | sudo tee /sys/module/lha_centos9_avc_capture/parameters/debug_capture
```

## 6. 采集与归一化逻辑

probe 函数签名与当前目标 tracepoint 对齐，能接收到：

- `sad`
  SELinux 审计数据
- `scontext`
- `tcontext`
- `tclass`

当前只处理 `sad->denied != 0` 的事件。满足条件时会构造：

- `timestamp_ns`
  取 `ktime_get_real_ns()`
- `pid`
  取 `task_tgid_nr(current)`
- `tid`
  取 `task_pid_nr(current)`
- `comm`
  取 `current->comm`
- `scontext`
  直接复制 tracepoint 参数
- `tcontext`
  直接复制 tracepoint 参数
- `tclass`
  直接复制 tracepoint 参数
- `permissive`
  当 `sad->result == 0` 时记为 `1`
- `denied`
  固定记为 `1`

最后调用 `lha_centos9_record_avc_event()` 写入 resolver 缓存。

## 7. deny 权限位到 `perm` 的映射

当前模块只把一部分常用 deny 位解码成 resolver 侧使用的权限字符串：

- `open`
- `read`
- `write`
- `append`
- `exec`
- `search`
- `unknown`

映射规则如下：

- 命中 `OPEN` 位 -> `open`
- 命中 `READ` 位 -> `read`
- 命中 `APPEND` 位 -> `append`
- 未命中 `APPEND` 但命中 `WRITE` 位 -> `write`
- `tclass == "dir"` 且命中目录搜索位 -> `search`
- 非目录目标且命中 `execute` -> `exec`
- 其他当前还没有显式建模的 deny 位 -> `unknown`

这套映射是为了和 resolver 生成的 `request.perm` 使用同一套命名，从而支持字符串级匹配。

如果同一条 AVC deny 同时包含“已建模权限”和“未建模权限”，当前实现会输出类似：

```text
read|unknown
```

如果整条 deny 都只包含当前系统未建模的权限，则会输出：

```text
unknown
```

## 8. 与 resolver 的配合方式

推荐链路是：

1. 加载 `lha_centos9_resolver.ko`
2. 加载 `lha_centos9_avc_capture.ko`
3. 外部抓取模块把 hook 事件交给 resolver
4. resolver 在解析完成后，从内部 AVC 缓存里寻找匹配 deny
5. 命中后输出 `policy_result = deny`

如果未命中 deny，resolver 会输出 `inferred_allow` 或 `unknown`，具体取决于匹配键是否完整、是否出现歧义。

## 9. 如何验证 capture 是否真的工作

建议同时打开：

- `lha_centos9_avc_capture.debug_capture=1`
- `lha_centos9_resolver.debug_avc_cache=1`

然后执行：

```bash
sudo dmesg -w
```

如果一条真实 AVC deny 被成功写入 resolver 缓冲区，通常会看到：

```text
lha_centos9_avc_capture: captured avc deny ...
lha_centos9_avc_capture: forwarded avc deny to resolver cache ...
lha_centos9_resolver: cached avc deny index=...
```

如果只能看到 `captured avc deny`，但后面出现 `failed to forward ... -22`，说明这条事件没有满足 resolver 的入缓存条件。

## 10. 局限性

当前模块的局限包括：

- 只记录 deny 事件，不记录 allow
- 依赖 `selinux_audited` tracepoint 的参数形态，与目标内核版本绑定
- `perm` 只覆盖当前 resolver 使用的那一组常见权限语义
- 事件时间戳是在 probe 执行时生成，不是 tracepoint 原始结构体里自带的时间戳

因此它适合做当前项目的 v1 级 deny 关联，但不能单独作为完整 SELinux 决策审计方案。
