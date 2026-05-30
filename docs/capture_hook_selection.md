# 抓取钩子选择说明：为什么只保留 selinux_file_open

本文档记录 `lha_centos9_capture.ko` 在 CentOS Stream 9 / aarch64 上从“探测三个 SELinux LSM 钩子”收敛为“只探测 `selinux_file_open`”的原因，包含三个钩子都保留时的真实实验现象、崩溃机理分析，以及保留单钩子后的能力边界。

> 适用环境：CentOS Stream 9，内核 `5.14.0-694.el9.aarch64`。
> 相关代码：`kmod/lha_centos9_capture.c`。

---

## 1. 背景：capture 模块在做什么

`lha_centos9_capture.ko` 用 **kprobe（函数入口探针，而非 kretprobe）** 挂在 SELinux 的 LSM hook 函数上，在 hook 现场抓取参数并建立稳定引用（`get_file` / `igrab` / `get_task_struct` / `get_current_cred`）��然后通过私有 workqueue 投递给 `lha_centos9_resolver.ko` 做富化和事件流输出。

之所以用 kprobe 入口探针而不用 kretprobe：aarch64 内核开启 Shadow Call Stack（`CONFIG_SHADOW_CALL_STACK`）/ 指针认证（`CONFIG_ARM64_PTR_AUTH_KERNEL`）时，kretprobe 改写返回地址（x30/LR）可能崩溃。只探入口就不碰返回地址。代价是拿不到 hook 返回值，所以 `ret` 恒记为 0（allow），策略判定交给 AVC 关联。

候选的三个钩子：

| 钩子 | 触发时机 | 调用上下文 | 频率 |
| --- | --- | --- | --- |
| `selinux_inode_permission(inode, mask)` | **每一个路径分量**的访问检查（`inode_permission` → `may_lookup` 等） | 包含 **RCU-walk（`MAY_NOT_BLOCK`）**、可关中断的原子路径 | 极高 |
| `selinux_file_permission(file, mask)` | **每一次 read / write / sendfile** | 进程上下文，但在读写快路径上 | 极高 |
| `selinux_file_open(file)` | **每一次 open()**（`do_dentry_open`） | 干净的可睡眠进程上下文 | 中低 |

---

## 2. 实验现象：三个钩子都保留

### 2.1 复现步骤

```bash
bash lha_start.sh
```

`lha_start.sh` 的加载顺序为：

```
lha_centos9_resolver  →  lha_centos9_avc_capture  →  lha_centos9_event_channel  →  lha_centos9_capture
```

### 2.2 观察到的输出

前 4 步全部正常：旧模块卸载、内核模块编译、用户态 `lha-eventd` 编译、前三个内核模块加载成功。**问题精确地发生在加载第四个模块 `lha_centos9_capture` 的那一刻**：

```text
=== Step 5: Load modules ===
[*] Loading lha_centos9_resolver
[*] Loading lha_centos9_avc_capture
[*] Loading lha_centos9_event_channel
[*] Loading lha_centos9_capture
Read from remote host 172.16.214.134: Connection reset by peer
Connection to 172.16.214.134 closed.
client_loop: send disconnect: Broken pipe
```

即：`insmod lha_centos9_capture.ko` 之后，SSH 连接立刻被重置，**整台 CentOS 直接重启**。因为是硬重启，没有留下可读的 `dmesg`（除非配置了 kdump/vmcore）。

### 2.3 现象特征归纳

- 崩溃**只**与第四个模块（capture）相关；前三个模块单独加载都稳定。
- 崩溃是**瞬时**的：探针一武装（register 完成、init 返回），系统在极短时间内复位，符合内核 panic / hard-lockup 触发看门狗复位的特征（RHEL 系默认 `panic_on_oops`，oops 即 panic；硬锁也会被 NMI watchdog 复位）。
- 把 capture 从 kretprobe 改成 kprobe 入口探针（提交 `d156375`）**并不能消除**该现象——说明根因不是返回地址改写。

---

## 3. 崩溃机理分析

我们逐项排除了“写错了”的常见可能，结论是：**代码本身的签名/结构/引用计数都是对的，崩溃来自“探测对象选错了”——把探针挂在了内核最热的两个 LSM 钩子上，并在原子上下文里做重活。**

### 3.1 已排除的因素（都是对的）

- **hook 函数签名匹配**：`selinux_inode_permission(struct inode*, int)`、`selinux_file_permission(struct file*, int)`、`selinux_file_open(struct file*)` 与内核树 `security/selinux/hooks.c` 完全一致，`LHA_ARG0/ARG1` 取参正确。
- **AVC 镜像结构匹配**：`struct lha_selinux_audit_data` 各字段偏移与内核 `security/selinux/include/avc.h` 的 `struct selinux_audit_data` 一致。
- **引用计数平衡**：handler 抓一次、worker 释放一次，无双重释放、无泄漏。

### 3.2 真正的根因：把探针挂在最热路径上

`selinux_inode_permission` 和 `selinux_file_permission` 是内核里调用最频繁的 LSM 回调：

- `selinux_inode_permission` 在**每一个路径分量**上触发，并且会在 **RCU-walk（`MAY_NOT_BLOCK`）**这种延迟极敏感、不可睡眠的快路径中被调用。
- `selinux_file_permission` 在**每一次读写**上触发。

而我们的 kprobe pre-handler 在**原子 / 关中断上下文**里做了：`kzalloc(GFP_ATOMIC)` + 抓多个引用 + `queue_work()`。在全系统系统调用速率下，这相当于在最热路径上、原子上下文里持续做内存分配与排队；再叠加后端 `WQ_UNBOUND`（最多数百并发）worker 每条事件都跑 `d_path()` + 两次 `security_*secctx` + 自旋锁里遍历 128 条 AVC 缓存——系统几乎无法向前推进，迅速进入锁死/恐慌并被复位。

这也解释了为什么 kretprobe→kprobe 的修改没用：问题从来不是“改返回地址”，而是“在错误的、过热的函数上、用原子上下文做了太多事”。

### 3.3 次要隐患：原子上下文里释放引用

旧实现的丢弃路径（队列满 / `GFP_ATOMIC` 失败）会在 **kprobe 原子上下文**里直接调用 `iput()`/`fput()`：

- `iput()` 可能进入 `iput_final()` → 睡眠（“sleeping while atomic” → BUG）。
- `fput()` 会推迟到 task work，本身原子安全，但不应在丢弃热路径上做。

在内存压力下 `GFP_ATOMIC` 失败会走丢弃路径，从而在原子上下文里触发上述操作，进一步增加崩溃概率。

---

## 4. 决策：只保留 selinux_file_open

`selinux_file_open` 与上面两个钩子完全不同：

- **只在 `open()` 时触发一次**，频率可控；
- 运行在 `do_dentry_open` 的**干净可睡眠进程上下文**，不会落到 RCU-walk / 关中断快路径；
- worker 的解析路径（`d_path`、`getsecctx`、`kmalloc(GFP_KERNEL)`）不会反过来再产生 `open()`，几乎没有自放大递归。

因此把探测面收敛到 `selinux_file_open` 一个钩子，是消除瞬时重启、同时保留核心能力的最稳妥做法。

同时在代码里做了原子上下文加固（见 `kmod/lha_centos9_capture.c`）：

- **先确认要入队、再抓引用**：在容量检查 + `kzalloc` 成功之前不抓任何引用，任何丢弃路径都在抓引用之前就 `return`，从根本上保证原子上下文里**永远不需要释放引用**；
- 引用**只**在可睡眠的 worker 里释放。

---

## 5. 保留单钩子后的能力边界

### 5.1 仍然能拿到的信息（来自 file_open 一条事件）

- 完整文件路径（`d_path(&file->f_path, ...)`，最接近用户态真实路径）；
- 打开权限解码（`open` / `read` / `write` / `append` / `exec`，来自 `f_flags`）；
- 主体身份：`pid` / `tid` / `comm` / `scontext`；
- 目标信息：`dev` / `ino` / `type` / `tclass` / `tcontext`；
- 策略结果：经 `lha_centos9_avc_capture.ko` 的 AVC deny 关联，输出 `deny` / `inferred_allow` / `unknown`。

### 5.2 会失去的信息

- 纯读/写过程中的细粒度 `file_permission` 事件（即同一个已打开 fd 上后续每次 read/write 不再单独成事件）；
- 路径遍历阶段的 `inode_permission` 事件（对未经 open 的中间路径分量的访问检查）。

对于“谁、用什么权限、打开了哪个文件、是否被 SELinux 拒绝”这类文件操作审计 / 异常检测场景，`file_open` 已经足够。

### 5.3 关于重新启用另两个钩子

**不建议**在 CentOS Stream 9 / aarch64 上重新启用 `selinux_inode_permission` / `selinux_file_permission` 入口探针。如确有“逐次读写 / 逐路径分量”采集的硬需求，应改用对热路径更友好的机制（如 eBPF LSM / tracing，或带严格采样与背压的专用方案），而不是直接再挂这两个 kprobe。

---

## 6. 验证

在目标机上重新执行：

```bash
bash lha_start.sh
```

预期：第 5 步加载 `lha_centos9_capture` 不再导致重启，`lha-eventd` 正常起来；产生 open 事件后查看日志：

```bash
tail -f /var/log/lha/$(date +%Y-%m-%d).log
dmesg | grep lha_centos9_capture   # 应看到 "hooking selinux_file_open"
```
