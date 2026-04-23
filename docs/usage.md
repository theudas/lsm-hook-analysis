# 使用说明

本文档说明刚克隆好项目后应该做什么，以及每一步的用途。文档分为两条路径：

- 用户态验证路径：在普通开发环境中验证通用解析逻辑。
- 内核态运行路径：在 Linux/CentOS Stream 9 中编译并加载 `.ko` 模块，进行假事件注入验证。

## 1. 前置条件

### 1.1 用户态验证需要

- `make`
- C 编译器，例如 `cc` 或 `gcc`

这部分只编译 `src/` 和 `tests/`，不需要 Linux 内核头文件。

### 1.2 内核态运行需要

- Linux 环境，推荐 CentOS Stream 9
- root 权限或 sudo 权限
- 当前运行内核对应的构建目录
- 内核模块构建工具链

通常需要存在：

```bash
/lib/modules/$(uname -r)/build
```

用途：

- `kmod/` 目录里的代码要编译成 `.ko` 内核模块。
- 编译外部内核模块必须使用当前运行内核匹配的 headers/build 目录。
- macOS 不能加载 Linux `.ko`，所以内核态部分必须在 Linux 上执行。

## 2. 克隆后进入项目

```bash
git clone git@github.com:theudas/lsm-hook-analysis.git
cd lsm-hook-analysis
```

用途：

- 获取项目源码。
- 后续所有命令默认从项目根目录开始执行。

如果项目已经在本地，直接进入目录即可：

```bash
cd lsm-hook-analysis
```

## 3. 先跑用户态构建

```bash
make
```

用途：

- 编译用户态通用解析层。
- 生成静态库 `build/liblha.a`。
- 这一步验证 `src/lha_resolver.c` 和 `src/lha_json.c` 至少能在用户态编译通过。

相关文件：

- `Makefile`
- `src/lha_resolver.c`
- `src/lha_json.c`

## 4. 跑用户态测试

```bash
make test
```

用途：

- 编译并运行 `tests/test_resolver.c`。
- 使用 mock 的 `kernel ops` 验证 hook 路由、字段填充、权限解码和 JSON 输出。
- 这一步不依赖真实内核 hook，也不会加载内核模块。

成功时会看到：

```text
ok
```

## 5. 编译内核模块

进入 `kmod/`：

```bash
cd kmod
make
```

用途：

- 调用 Linux 内核 Kbuild 系统。
- 根据 `kmod/Makefile` 编译两个外部内核模块。

生成的主要产物：

- `lha_centos9_resolver.ko`
- `lha_centos9_injector.ko`

两个模块的作用不同：

- `lha_centos9_resolver.ko`
  生产模块，导出 resolver API，真实抓取模块应该调用它。
- `lha_centos9_injector.ko`
  自测模块，只负责 debugfs 假事件注入。

如果你要指定内核构建目录，可以这样：

```bash
make KDIR=/path/to/kernel/build
```

用途：

- 当 `/lib/modules/$(uname -r)/build` 不是你想使用的构建目录时，手动指定 Kbuild 位置。

## 6. 卸载旧模块

如果之前已经加载过旧版模块，先查看：

```bash
lsmod | grep lha
```

用途：

- 确认内核里是否已有旧的 `lha_*` 模块。
- 如果旧模块还在，直接 `insmod` 新模块通常会失败。

推荐按依赖顺序卸载：

```bash
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_resolver
```

用途：

- 先卸载依赖 resolver 的 injector。
- 再卸载 resolver。

如果你只加载过旧的单模块版本，通常只需要：

```bash
sudo rmmod lha_centos9_resolver
```

如果提示模块正在使用：

```text
Module lha_centos9_resolver is in use
```

说明还有其他模块依赖它，例如 injector 或你们自己的 hook 抓取模块。先卸载依赖模块，再卸载 resolver。

不建议使用：

```bash
sudo rmmod -f <module>
```

原因：

- 强制卸载内核模块有导致系统崩溃的风险。

## 7. 加载生产 resolver 模块

```bash
sudo insmod lha_centos9_resolver.ko
```

用途：

- 将生产 resolver 模块加载进内核。
- 对外导出以下 API：
  - `lha_centos9_resolve_event()`
  - `lha_centos9_format_json()`

加载后查看：

```bash
lsmod | grep lha
dmesg | tail
```

用途：

- `lsmod` 确认模块已经在内核中。
- `dmesg` 查看模块加载日志。

生产环境只加载这个模块即可。真实 hook 抓取模块应该在它之后加载，并调用它导出的 API。

## 8. 加载假事件注入模块

如果你要进行自测，再加载 injector：

```bash
sudo insmod lha_centos9_injector.ko
```

用途：

- 加载 debugfs 自测模块。
- 创建假事件注入入口。
- 通过 resolver 导出的 API 验证完整解析流程。

加载后查看：

```bash
lsmod | grep lha
dmesg | tail
```

预期能看到两个模块：

```text
lha_centos9_injector
lha_centos9_resolver
```

注意：

- `lha_centos9_injector.ko` 依赖 `lha_centos9_resolver.ko`。
- 加载顺序应先 resolver，后 injector。
- 生产环境不需要加载 injector。

## 9. 挂载 debugfs

如果系统还没有挂载 debugfs，执行：

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

用途：

- injector 通过 debugfs 暴露测试入口。
- 没有 debugfs 时，无法通过 `/sys/kernel/debug/lha_centos9/inject` 注入假事件。

确认入口是否存在：

```bash
ls -l /sys/kernel/debug/lha_centos9
```

预期看到：

```text
inject
last_json
```

这两个文件的含义：

- `inject`
  写入测试命令，触发假事件注入。
- `last_json`
  读取最近一次 resolver 生成的 JSON。

## 10. 执行假事件注入

### 10.1 注入 inode_permission 样例

```bash
echo sample_inode | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

用途：

- 构造一个 `selinux_inode_permission` 类型的假事件。
- 目标对象是 `/tmp`。
- `mask` 使用 `MAY_EXEC`。
- 用来验证 inode 路径恢复、主体上下文、目标上下文和权限解码。

### 10.2 注入 file_open 样例

```bash
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

用途：

- 构造一个 `selinux_file_open` 类型的假事件。
- 目标对象是 `/etc/hosts`。
- 用来验证 `file *` 路径恢复和 `open|read` 权限语义。

### 10.3 注入 file_permission 样例

```bash
echo sample_append | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

用途：

- 构造一个 `selinux_file_permission` 类型的假事件。
- 目标对象是 `/tmp/lha_inject.log`。
- `mask` 使用 `MAY_WRITE`。
- 文件以 `O_APPEND` 打开，因此权限会被解析为 `append`。
- `ret` 被故意设置为 `-EACCES`，用于验证 `runtime_result=deny`。

## 11. 查看 JSON 结果

```bash
cat /sys/kernel/debug/lha_centos9/last_json
```

用途：

- 查看最近一次假事件经过 resolver 后生成的结构化 JSON。

结果中至少应包含：

- `hook`
- `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

其中：

- `subject`
  表示触发事件的任务信息。
- `request`
  表示访问请求和权限语义。
- `target`
  表示目标资源路径、inode、SELinux 上下文等。
- `result`
  表示 hook 返回值和运行时允许/拒绝结果。

## 12. 生产接入方式

生产环境不通过 `inject` 文件写假事件。

正确链路是：

1. 外部抓取模块在真实 SELinux hook 现场拿到参数和返回值。
2. 外部抓取模块保存稳定引用。
3. 外部抓取模块组装 `struct lha_capture_event_v1`。
4. 在 workqueue/kthread 中调用 `lha_centos9_resolve_event()`。
5. 如需 JSON，再调用 `lha_centos9_format_json()`。
6. 外部抓取模块负责释放引用。

用途：

- `lha_centos9_resolver.ko` 专注做解析。
- 真实 hook 采集逻辑由外部模块负责。
- injector 只用于开发、调试和自测。

详细接入方式见：

```text
docs/api.md
```

## 13. 卸载模块

自测结束后，按依赖顺序卸载：

```bash
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_resolver
```

用途：

- 先卸载调用 resolver API 的 injector。
- 再卸载被依赖的 resolver。

确认卸载完成：

```bash
lsmod | grep lha
```

如果没有输出，说明相关模块已经卸载。

## 14. 清理构建产物

清理用户态构建产物：

```bash
cd /path/to/lsm-hook-analysis
make clean
```

用途：

- 删除根目录构建产生的 `build/`。

清理内核模块构建产物：

```bash
cd /path/to/lsm-hook-analysis/kmod
make clean
```

用途：

- 调用 Kbuild 清理 `.o`、`.ko`、`.mod` 等内核模块构建产物。

## 15. 常见问题

### 15.1 `insmod` 提示 File exists

原因：

- 同名模块已经加载。

处理：

```bash
lsmod | grep lha
sudo rmmod lha_centos9_injector
sudo rmmod lha_centos9_resolver
sudo insmod lha_centos9_resolver.ko
```

### 15.2 `rmmod` 提示 Module is in use

原因：

- 还有其他模块依赖它。

处理：

- 先卸载依赖模块，例如 `lha_centos9_injector` 或真实 hook 抓取模块。
- 再卸载 `lha_centos9_resolver`。

### 15.3 找不到 `/sys/kernel/debug/lha_centos9`

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

### 15.4 `make` 内核模块失败

可能原因：

- 当前系统没有安装内核 headers。
- `/lib/modules/$(uname -r)/build` 不存在。
- 当前不是 Linux 环境。
- 内核版本和构建目录不匹配。

处理：

- 在目标 Linux/CentOS Stream 9 机器上编译。
- 安装匹配当前运行内核的开发包。
- 或用 `make KDIR=/path/to/kernel/build` 指定正确构建目录。

### 15.5 假事件注入不等于真实 hook

说明：

- 假事件是 injector 自己构造的测试输入。
- 它用来验证 resolver API、路径解析、上下文解析和 JSON 输出。
- 它不表示系统真的发生了一次 SELinux hook 拦截。

真实事件需要外部抓取模块接入，详见 `docs/api.md`。
