# `lha_centos9_capture.ko` 模块说明

## 1. 模块职责

`lha_centos9_capture.ko` 是本项目的真实 LSM hook 捕获模块。它通过 kretprobe 机制拦截内核中的 SELinux hook 函数，在现场采集参数和返回值，并通过私有 workqueue 异步交给 resolver 做语义解析。

它做三件事：

- 在 hook 入口捕获函数参数并建立稳定引用
- 在 hook 返回时获取返回值，组装 `struct lha_capture_event_v1`
- 通过 workqueue 将事件投递给 `lha_centos9_resolve_event()`

## 2. 当前 hook 覆盖范围

模块通过 kretprobe 挂载以下 3 个 SELinux 函数：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

每个函数对应一组独立的 entry handler 和 return handler。

## 3. 依赖关系

该模块依赖 `lha_centos9_resolver.ko` 提供的：

- `lha_centos9_resolve_event()`

模块通过 `MODULE_SOFTDEP("pre: lha_centos9_resolver")` 声明了这一点，但实际加载时仍建议显式先加载 resolver。

## 4. 依赖的内核能力

当前实现要求目标内核提供：

- kretprobe 支持（`register_kretprobe()` / `unregister_kretprobe()`）
- SELinux 的 `selinux_inode_permission`、`selinux_file_open`、`selinux_file_permission` 函数符号可被 kprobe 探测

## 5. 架构支持

模块通过编译期宏适配不同架构的函数参数获取方式：

- `CONFIG_X86_64`：通过 `regs->di`、`regs->si` 读取参数
- `CONFIG_ARM64`：通过 `regs->regs[0]`、`regs->regs[1]` 读取参数

不支持的架构会在编译时报错。

## 6. 工作流程

### 6.1 Entry handler（不可睡眠上下文）

在 hook 函数入口执行，完成以下操作：

1. 从寄存器中提取函数参数（`inode`/`file`/`mask`）
2. 为参数对象建立稳定引用：
   - `task`：`get_task_struct(current)`
   - `cred`：`get_current_cred()`
   - `inode`：`igrab(inode)`
   - `file`：`get_file(file)`
3. 记录时间戳 `ktime_get_real_ns()`
4. 将数据保存到 kretprobe 的 per-instance data 中

如果参数无效（空指针或 `igrab` 失败），entry handler 返回 `1`，跳过该实例。

### 6.2 Return handler（不可睡眠上下文）

在 hook 函数返回时执行，完成以下操作：

1. 通过 `regs_return_value(regs)` 获取返回值
2. 检查 pending 计数是否超过 `max_pending` 上限
3. 分配 `struct lha_pending_event`（`GFP_ATOMIC`）
4. 组装 `struct lha_capture_event_v1`
5. 将 work 投递到私有 workqueue `lha_capture_wq`

如果分配失败或 pending 数超限，会释放所有已建立的引用并丢弃该事件。

### 6.3 Workqueue worker（可睡眠上下文）

1. 调用 `lha_centos9_resolve_event()` 解析事件
2. 如果 `event_channel` 已加载，resolver 会自动将结果送入事件流
3. 释放所有稳定引用
4. 释放 `pending` 内存
5. 递减 `pending_count`

## 7. 模块参数

- `max_pending`（默认 `4096`，可动态修改）

控制同时排队等待 resolver 处理的最大事件数。超过此上限时，新事件会被丢弃以防止内存耗尽。

加载时指定：

```bash
sudo insmod lha_centos9_capture.ko max_pending=8192
```

模块已加载后在线修改：

```bash
echo 8192 | sudo tee /sys/module/lha_centos9_capture/parameters/max_pending
```

## 8. 加载与卸载

### 8.1 推荐加载顺序

```bash
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_avc_capture.ko      # 可选，启用 deny 关联
sudo insmod lha_centos9_event_channel.ko    # 可选，启用连续事件输出
sudo insmod lha_centos9_capture.ko
```

加载成功后 `dmesg` 会显示：

```text
lha_centos9_capture: loaded, hooking 3 SELinux LSM functions (max_pending=4096)
```

### 8.2 卸载顺序

```bash
sudo rmmod lha_centos9_capture
sudo rmmod lha_centos9_event_channel
sudo rmmod lha_centos9_avc_capture
sudo rmmod lha_centos9_resolver
```

卸载时 `dmesg` 会显示各 kretprobe 的 missed 计数：

```text
lha_centos9_capture: unloaded (missed: inode_perm=0 file_open=0 file_perm=0)
```

`missed` 大于 0 表示 kretprobe 的 `maxactive` 实例不够用，有事件在高并发下被跳过。

## 9. 引用管理

模块严格遵守 resolver 的引用生命周期约束：

- entry handler 中建立引用
- worker 中释放引用
- 如果事件被丢弃（pending 超限或分配失败），在 return handler 中立即释放引用

对应关系：

| 对象 | 获取 | 释放 |
|------|------|------|
| `task` | `get_task_struct()` | `put_task_struct()` |
| `cred` | `get_current_cred()` | `put_cred()` |
| `inode` | `igrab()` | `iput()` |
| `file` | `get_file()` | `fput()` |

## 10. 完整链路验证

推荐使用仓库根目录下的 `test_capture.sh` 脚本进行一键测试：

```bash
sudo bash test_capture.sh
```

脚本会自动完成编译、加载、触发事件、验证日志、显示统计和卸载清理。

手动验证步骤：

1. 按 8.1 的顺序加载所有模块
2. 启动 `lha-eventd`：`sudo ./userspace/lha-eventd &`
3. 触发文件操作：`cat /etc/hosts`、`ls /tmp`
4. 检查日志：`cat /var/log/lha/$(date +%Y-%m-%d).log`
5. 检查 `dmesg | grep lha_centos9`

## 11. 与其他模块的配合

- **resolver**：capture 将事件交给 resolver 解析，resolver 负责填充主体/目标/权限/结果
- **event_channel**：如果已加载，resolver 会自动将解析结果送入 `/dev/lha_centos9_event_stream`
- **avc_capture**：如果已加载，resolver 会在解析完成后从 AVC 缓存中关联 deny 证据，补充 `policy_result`
- **lha-eventd**：用户态 daemon 从 event_channel 读取事件并写入 NDJSON 日志

## 12. 局限性

当前模块的局限包括：

- 仅支持 x86_64 和 aarch64 架构
- 仅覆盖 3 类 SELinux hook，不覆盖 `selinux_task_*`、`selinux_socket_*` 等
- kretprobe 的 `maxactive`（默认 64）在极端高并发下可能不够用，导致部分事件被跳过
- 事件丢弃（pending 超限）不会在日志中报告，仅通过 `dmesg` 中卸载时的 `missed` 计数体现
- 依赖内核允许对 SELinux 函数进行 kprobe 探测；部分加固内核可能禁用此能力
