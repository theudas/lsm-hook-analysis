# 使用说明

本文档只描述当前仓库里真实存在的内核态用法：

- 编译 `kmod/`
- 加载和卸载 3 个模块
- 用 injector 做本地自测
- 了解生产接入时的最小调用顺序

## 1. 前置条件

需要满足以下条件：

- Linux 环境
- 可用的内核模块编译工具链
- root 或 sudo 权限
- 与目标运行内核匹配的模块构建目录

默认构建目录是：

```bash
/lib/modules/$(uname -r)/build
```

如果这个目录不存在，通常说明当前环境缺少匹配的内核开发包，或者当前不是可编译内核模块的 Linux 环境。

## 2. 编译模块

进入 `kmod/` 目录后执行：

```bash
cd /path/to/lsm-hook-analysis/kmod
make
```

如果要显式指定内核构建目录：

```bash
make KDIR=/path/to/kernel/build
```

成功后会生成：

- `lha_centos9_resolver.ko`
- `lha_centos9_injector.ko`
- `lha_centos9_avc_capture.ko`

## 3. 加载模块

最小生产加载方式只需要 resolver：

```bash
sudo insmod lha_centos9_resolver.ko
```

如果需要自测，再加载 injector：

```bash
sudo insmod lha_centos9_injector.ko
```

如果需要自动采集真实 AVC deny，再加载 AVC capture：

```bash
sudo insmod lha_centos9_avc_capture.ko
```

推荐检查：

```bash
lsmod | grep lha
dmesg | tail
```

## 4. 挂载 debugfs

只有 injector 会创建 debugfs 入口。若系统还未挂载 debugfs，请执行：

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

随后检查：

```bash
ls -l /sys/kernel/debug/lha_centos9
```

若 injector 已正常加载，目录下应包含：

- `inject`
- `last_json`

## 5. 执行 injector 自测

### 5.1 `sample_inode`

```bash
echo sample_inode | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一条 `selinux_inode_permission` 样例，目标是 `/tmp`，请求权限来自 `LHA_MAY_EXEC`。

### 5.2 `sample_open`

```bash
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一条 `selinux_file_open` 样例，目标是 `/etc/hosts`。当前这条样例不额外写入 AVC deny，因此 `policy_result` 通常会得到 `inferred_allow`。

### 5.3 `sample_append`

```bash
echo sample_append | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一条 `selinux_file_permission` 样例，目标是 `/tmp/lha_inject.log`。injector 会先写入一条匹配的 AVC deny，因此最终 `policy_result` 应为 `deny`。

## 6. 查看输出

读取：

```bash
cat /sys/kernel/debug/lha_centos9/last_json
```

输出 JSON 中的固定顶层字段包括：

- `hook`
- `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

其中最常关注的是：

- `result.runtime_result`
  基于 hook 返回值的运行时结果
- `result.policy_result`
  基于 resolver 内置 AVC deny 关联得到的策略结果

## 7. 生产接入的最小顺序

生产环境不通过 `inject` 文件写假事件。最小接入顺序如下：

1. 在真实 hook 现场抓取参数和最终返回值。
2. 在 hook 现场为 `task`、`cred`、`inode` 或 `file` 建立稳定引用。
3. 组装 `struct lha_capture_event_v1`。
4. 在 `workqueue` 或 `kthread` 中调用 `lha_centos9_resolve_event()`。
5. 如需字符串输出，再调用 `lha_centos9_format_json()`。
6. 由调用方释放之前建立的引用。

如果要启用 deny 关联，有两种方式：

- 加载 `lha_centos9_avc_capture.ko`
- 由你们自己的 AVC 模块调用 `lha_centos9_record_avc_event()`

详细 API 见 [resolver_api_access_guide.md](resolver_api_access_guide.md)。

## 8. 开启 AVC 调试日志

如果要验证 `lha_centos9_avc_capture.ko` 是否真的抓到了真实 AVC deny，并成功写入 resolver 内部缓存，可以打开两个模块参数：

- `lha_centos9_avc_capture.debug_capture`
  打印“tracepoint 已抓到 AVC deny”和“是否成功转发给 resolver”
- `lha_centos9_resolver.debug_avc_cache`
  打印“resolver 是否接受并写入了 AVC 环形缓存”

### 8.1 在加载时开启

```bash
sudo insmod lha_centos9_resolver.ko debug_avc_cache=1
sudo insmod lha_centos9_avc_capture.ko debug_capture=1
```

### 8.2 模块已加载后在线开启

```bash
echo 1 | sudo tee /sys/module/lha_centos9_resolver/parameters/debug_avc_cache
echo 1 | sudo tee /sys/module/lha_centos9_avc_capture/parameters/debug_capture
```

### 8.3 观察日志

```bash
sudo dmesg -w
```

成功路径下，通常会看到：

```text
lha_centos9_avc_capture: captured avc deny ...
lha_centos9_avc_capture: forwarded avc deny to resolver cache ...
lha_centos9_resolver: cached avc deny index=...
```

如果抓到了 AVC deny 但 resolver 没接收，会看到：

```text
lha_centos9_avc_capture: failed to forward avc deny to resolver cache: -22
lha_centos9_resolver: reject avc cache insert: ...
```

这通常意味着 AVC 事件缺少当前 resolver 所需的关键匹配字段，最常见的是 `perm` 为空。

### 8.4 重要提醒

`sample_append` 不能用来验证 `avc_capture` 是否工作，因为 injector 会直接调用 `lha_centos9_record_avc_event()` 往 resolver 缓冲区写一条匹配事件，而不是依赖真实 `selinux_audited` tracepoint。

要验证 `avc_capture`，必须先在系统里触发一条真实 AVC deny，再看上面的调试日志。

## 9. 卸载模块

卸载时应先卸载依赖 resolver 的模块：

```bash
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_avc_capture
sudo rmmod lha_centos9_resolver
```

如果 `rmmod lha_centos9_resolver` 提示 `Module is in use`，说明还有 injector 或其他外部模块依赖它。

## 10. 清理构建产物

```bash
cd /path/to/lsm-hook-analysis/kmod
make clean
```

## 11. 常见问题

### 11.1 `make` 失败

优先检查：

- `/lib/modules/$(uname -r)/build` 是否存在
- 当前内核开发包是否与运行内核匹配
- 当前环境是否允许编译内核模块

### 11.2 `insmod` 提示 `File exists`

说明同名模块已经加载，先卸载旧模块再重新加载。

### 11.3 看不到 `/sys/kernel/debug/lha_centos9`

优先检查：

- `lha_centos9_injector.ko` 是否已加载
- debugfs 是否已挂载
- injector 是否在 `dmesg` 中报错

### 11.4 `sample_append` 没有得到 `deny`

这通常意味着：

- resolver 或 injector 加载异常
- AVC 缓存写入失败
- 本次样例没有成功执行完整的“两次 resolve + 一次 AVC 注入”流程

先查看 `dmesg`。

### 11.5 `avc_capture` 报 `failed to forward avc deny to resolver cache: -22`

这表示：

- `avc_capture` 已经抓到了真实 `selinux_audited` 事件
- 但 resolver 拒绝把这条 AVC 事件写入自己的缓冲区

优先检查调试日志里的：

- `perm` 是否为空
- `tclass` 是否为空
- `scontext` 和 `tcontext` 是否为空

如果这几个字段不完整，resolver 当前不会接受该事件。

### 11.6 injector 的输出不代表真实 hook

injector 只是固定样例自测入口，用于验证 resolver 和 JSON 输出，不等价于真实生产链路中的 hook 抓取。
