# CentOS Stream 9 运行说明

本文档只描述当前仓库这套模块在 CentOS Stream 9 场景下的运行前提、依赖关系和现实边界。

## 1. 当前保留的运行路径

仓库当前只保留 `kmod/` 这一条内核态运行路径，包含 3 个模块：

- `lha_centos9_resolver.ko`
  核心解析模块
- `lha_centos9_injector.ko`
  debugfs 自测模块
- `lha_centos9_avc_capture.ko`
  AVC deny 抓取模块

其中真正面向生产接入的是 resolver；另外两个模块分别用于自测和 deny 关联增强。

## 2. 为什么这套实现面向 CentOS Stream 9

仓库附带了 `centos-stream-9/` 内核树，当前文档中的关键运行前提都能在这棵树里交叉核实。

### 2.1 resolver 使用的安全接口

resolver 依赖以下公开安全接口：

- `security_cred_getsecid()`
- `security_secid_to_secctx()`
- `security_release_secctx()`
- `security_inode_getsecctx()`

这些接口在 `centos-stream-9/security/security.c` 中存在并导出，适合外部模块调用。

### 2.2 AVC capture 使用的 tracepoint

AVC capture 依赖：

- `selinux_audited` tracepoint
- `for_each_kernel_tracepoint()`

仓库内核树中可以找到：

- `centos-stream-9/include/trace/events/avc.h`
  定义 `TRACE_EVENT(selinux_audited, ...)`
- `centos-stream-9/security/selinux/avc.c`
  调用 `trace_selinux_audited(...)`
- `centos-stream-9/kernel/tracepoint.c`
  导出 `for_each_kernel_tracepoint()`

因此，当前 `lha_centos9_avc_capture.ko` 是按这套内核结构编写的。

## 3. 推荐的运行模型

当前实现建议采用“hook 现场抓取 + 异步解析”的模型。

推荐流程：

1. 外部抓取模块在 hook 现场采集参数和最终返回值。
2. 在 hook 现场为 `task`、`cred`、`inode` 或 `file` 建立稳定引用。
3. 把 `struct lha_capture_event_v1` 投递到 `workqueue` 或 `kthread`。
4. 在可睡眠上下文中调用 `lha_centos9_resolve_event()`。

这样做的原因是 resolver 当前会调用：

- `security_secid_to_secctx()`
- `security_inode_getsecctx()`
- `d_path()`
- `kmalloc(GFP_KERNEL)`

这些操作都不适合直接塞进不可睡眠上下文。

## 4. 模块之间的关系

推荐加载顺序：

1. `lha_centos9_resolver.ko`
2. `lha_centos9_avc_capture.ko`
3. 你们自己的 hook 抓取模块

如果只做自测，则使用：

1. `lha_centos9_resolver.ko`
2. `lha_centos9_injector.ko`

依赖关系如下：

- injector 通过 resolver 导出的 API 做样例解析
- AVC capture 通过 resolver 导出的 `lha_centos9_record_avc_event()` 写入 deny 缓存

## 5. 路径恢复的现实边界

当前实现里，`path` 的恢复精度取决于输入对象类型。

### 5.1 `file *`

对 `file_open` 和 `file_permission`，resolver 通过 `d_path(&file->f_path, ...)` 恢复路径。

这种方式通常更接近用户空间看到的真实路径。

### 5.2 `inode *`

对 `inode_permission`，resolver 只有 `inode`，没有完整的 mount/path 上下文，只能尝试：

- `d_find_alias(inode)`
- `dentry_path_raw()`

因此：

- 不保证得到全局绝对路径
- 失败时会回退到 dentry 名称或 `<unknown>`

## 6. `policy_result` 的当前能力边界

当前实现的 `policy_result` 依赖 AVC deny 关联，而不是完整的 SELinux 决策采集。

因此主解析路径中实际会得到：

- `deny`
- `inferred_allow`
- `unknown`

当前不应把它理解为“完整重建了策略层 allow/deny 决策”。

## 7. 构建与运行前提

模块构建仍以目标机器的运行内核为准。最常见的方式是使用：

```bash
/lib/modules/$(uname -r)/build
```

仓库中的 `centos-stream-9/` 更适合作为：

- 阅读实现依赖
- 核实接口存在性
- 做版本适配时查源码

它本身不是对当前系统直接可用的“万能构建目录”替代品。

## 8. 自测与生产的区别

`lha_centos9_injector.ko` 只能证明：

- resolver 模块能被调用
- 样例对象能被解析
- JSON 输出结构存在
- AVC deny 关联通路能被触发

它不能证明：

- 真实 hook 抓取模块接入无误
- 真实业务负载下的并发、时序和性能表现
- 所有目标路径和 SELinux 场景都能稳定恢复
  - mask：`MAY_WRITE`
  - `ret` 会被伪造为 `-EACCES`，用于验证 `runtime_result=deny`

每次注入后，可以读取最近一次生成的 JSON：

```bash
cat /sys/kernel/debug/lha_centos9/last_json
```

如果模块工作正常，你会看到一条完整 JSON，里面至少会包含：

- `hook`
- `subject`
- `request`
- `target`
- `result`

这个入口的定位是：

- 验证 resolver 自身能否正确运行
- 验证 injector 是否能通过导出的 resolver API 完成一次完整调用
- 验证 `task/cred + inode/file` 这条解析链路
- 验证 JSON 输出格式

它不是正式业务入口，只是为了方便调试和自测。

## 7. `policy_result` 说明

`policy_result` 现在由 resolver 主解析接口自动处理：

- 如果 resolver 内部 AVC 缓存中存在匹配 deny，输出 `deny`。
- 如果匹配字段完整但窗口内没有 deny，输出 `inferred_allow`。
- 如果缺少关键匹配字段，输出 `unknown`。

内部 AVC 缓存可以由 `lha_centos9_avc_capture.ko` 自动写入，也可以由外部 AVC 抓取模块调用 `lha_centos9_record_avc_event()` 写入。

注意：`ret` 仍然只表示 hook 的运行时返回值，不能单独代表 permissive 模式下的真实策略判定。

## 8. 你现在应该怎么理解整个项目

当前项目里：

- `kmod/` 是当前唯一保留的实现主线
- `lha_centos9_resolver.ko` 是生产侧解析模块
- `lha_centos9_avc_capture.ko` 是 AVC 抓取辅助模块
- `lha_centos9_injector.ko` 是自测辅助模块

如果你的目标是服务器实际部署，后续主要应继续推进 `kmod/` 目录和外部抓取模块的对接。
