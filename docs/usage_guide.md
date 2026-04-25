# 使用说明

本文档只描述当前仓库保留的内核态路径：编译 `kmod/`、加载 `.ko`、用 injector 自测，以及外部模块如何接入 resolver。

## 1. 前置条件

- Linux 环境，推荐 CentOS Stream 9
- `make` 与内核模块编译工具链
- root 权限或 sudo 权限
- 当前运行内核对应的构建目录

通常需要存在：

```bash
/lib/modules/$(uname -r)/build
```

## 2. 编译模块

```bash
cd /path/to/lsm-hook-analysis/kmod
make
```

如果你要手工指定内核构建目录：

```bash
make KDIR=/path/to/kernel/build
```

会生成两个模块：

- `lha_centos9_resolver.ko`
- `lha_centos9_injector.ko`

其中：

- `lha_centos9_resolver.ko` 是生产接入时真正依赖的解析模块
- `lha_centos9_injector.ko` 只是 debugfs 自测模块

## 3. 卸载旧模块

先检查：

```bash
lsmod | grep lha
```

如需卸载，按依赖顺序执行：

```bash
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_resolver
```

如果 `lha_centos9_resolver` 提示 `Module is in use`，说明还有 injector 或你们自己的抓取模块在依赖它，先卸载依赖方。

## 4. 加载模块

生产最小加载方式：

```bash
sudo insmod lha_centos9_resolver.ko
```

如果要做自测，再加载：

```bash
sudo insmod lha_centos9_injector.ko
```

加载后可检查：

```bash
lsmod | grep lha
dmesg | tail
```

## 5. 挂载 debugfs

如果系统还没有挂载 debugfs：

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

确认入口存在：

```bash
ls -l /sys/kernel/debug/lha_centos9
```

预期看到：

```text
inject
last_json
```

## 6. 执行 injector 自测

### 6.1 `sample_inode`

```bash
echo sample_inode | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一个 `selinux_inode_permission` 假事件，用来验证 inode 路径恢复、上下文解析和权限解码。

### 6.2 `sample_open`

```bash
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一个 `selinux_file_open` 假事件。当前 injector 不喂 AVC deny，因此 `policy_result` 会走 `inferred_allow`。

### 6.3 `sample_append`

```bash
echo sample_append | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

这会构造一个 `selinux_file_permission` 假事件，并额外喂一条匹配的 AVC deny，因此 `policy_result` 会是 `deny`。

## 7. 结果解读

读取：

```bash
cat /sys/kernel/debug/lha_centos9/last_json
```

结果里至少会包含：

- `hook`
- `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

其中 `result` 里的两个关键字段分别表示：

- `runtime_result`：hook 返回值对应的运行时结果
- `policy_result`：结合 `policy_state` 或 AVC 关联后得到的策略结果

## 8. 生产接入方式

生产环境不通过 `inject` 文件写假事件，正确链路是：

1. 外部抓取模块在真实 SELinux hook 现场拿到参数和返回值
2. 外部抓取模块保存稳定引用
3. 外部抓取模块组装 `struct lha_capture_event_v1`
4. 在 workqueue 或 kthread 中调用 `lha_centos9_resolve_event()`
5. 如需 JSON，再调用 `lha_centos9_format_json()`
6. 如需基于 AVC deny 决定 `policy_result`，再调用 `lha_centos9_apply_avc_policy_result()`
7. 外部抓取模块负责释放引用

详细接入方式见 `docs/api.md`。

## 9. 清理构建产物

```bash
cd /path/to/lsm-hook-analysis/kmod
make clean
```

这会清理 `.o`、`.ko`、`.mod` 等内核模块构建产物。

## 10. 常见问题

### 10.1 `insmod` 提示 `File exists`

说明同名模块已经加载，先执行卸载，再重新 `insmod`。

### 10.2 `rmmod` 提示 `Module is in use`

说明还有其他模块依赖 resolver，先卸载依赖模块，再卸载 resolver。

### 10.3 找不到 `/sys/kernel/debug/lha_centos9`

先确认已经加载 `lha_centos9_injector.ko`，再确认 debugfs 已挂载。

可能原因：

- 没有加载 `lha_centos9_injector.ko`。
- debugfs 没有挂载。
- injector 加载失败。

处理：

```bash
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko
sudo mount -t debugfs none /sys/kernel/debug
dmesg | tail
```

### 10.4 `make` 内核模块失败

可能原因：

- 当前系统没有安装内核 headers。
- `/lib/modules/$(uname -r)/build` 不存在。
- 当前不是 Linux 环境。
- 内核版本和构建目录不匹配。

处理：

- 在目标 Linux/CentOS Stream 9 机器上编译。
- 安装匹配当前运行内核的开发包。
- 或用 `make KDIR=/path/to/kernel/build` 指定正确构建目录。

### 10.5 假事件注入不等于真实 hook

说明：

- 假事件是 injector 自己构造的测试输入。
- 它用来验证 resolver API、路径解析、上下文解析和 JSON 输出。
- 它不表示系统真的发生了一次 SELinux hook 拦截。

真实事件需要外部抓取模块接入，详见 `docs/api.md`。
