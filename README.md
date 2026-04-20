# LSM Hook 参数与返回值分析

这是一个面向 SELinux LSM hook 的参数与返回值分析项目。

项目通过外置内核模块观测关键 hook 的调用现场，把参数、目标对象、路径信息、返回值与耗时导出为 JSON Lines，再由用户态脚本完成规则分析，帮助回答下面这类问题：

- 某个进程在访问什么对象
- 请求的是哪一类权限
- 请求发生在路径解析、打开文件还是后续 I/O 阶段
- hook 最终返回了什么结果
- 哪些访问行为更像拒绝、扫描、深路径遍历或异常重验证

整个实现不需要直接改动内核源码树中的 `security/selinux/hooks.c`。

## 项目目标

这个项目关注的不是“完整复刻 SELinux 决策过程”，而是把 LSM hook 的关键输入与输出结构化，形成一条可解释的分析链路：

1. 采集 hook 调用时的主体、客体、权限请求和返回值
2. 区分一次访问发生在 `path_walk`、`open` 还是 `io` 阶段
3. 输出稳定、可复用的 JSONL 数据
4. 在用户态给出第一版异常解释与行为提示

## 当前分析对象

当前模块观测了 3 个 SELinux 相关 hook：

- `selinux_inode_permission`
- `selinux_file_open`
- `selinux_file_permission`

这 3 个 hook 分别覆盖了目录遍历、文件打开与后续文件权限检查，是分析“谁以什么方式访问了什么对象，以及结果如何”的一个较小但足够清晰的切面。

## 整体架构

项目由两部分组成：

- 内核态
  - `lsm_hook_analysis.c`
  - 通过外置 `kretprobe` 模块采集 hook 入参与返回值
  - 通过 `debugfs` 导出结构化事件
- 用户态
  - `analyze_events.py`
  - 读取 JSONL 事件流并输出分析结果
  - `run_mock_tests.py`
  - 使用 mock 数据验证分析规则

处理流程如下：

```text
SELinux hook
  -> kretprobe 采集参数/返回值
  -> debugfs 导出 JSONL
  -> analyze_events.py 规则分析
  -> 输出 findings
```

## 目录结构

```text
lsm-hook-analysis/
├── README.md
├── Makefile
├── lsm_hook_analysis.c
├── analyze_events.py
├── run_mock_tests.py
└── mock-data/
    ├── normal_access.jsonl
    ├── deny_access.jsonl
    ├── echild_special.jsonl
    └── scan_and_slow_io.jsonl
```

## 采集的数据

每条事件都会导出为一行 JSON，核心字段如下：

- `subject`
  - 发起访问的主体信息
  - 包含 `tgid`、`tid`、`comm`、`secid`、`scontext`
- `request`
  - hook 请求信息
  - 包含 `hook`、`phase`、`mask_raw`、`file_flags`、`perm`
- `target`
  - 目标对象信息
  - 包含 `dev`、`ino`、`type`、`tclass`、`tcontext`
- `path`
  - 路径还原结果
  - 包含 `path`、`note`
- `result`
  - 返回值与解释
  - 包含 `ret`、`runtime_result`、`policy_result`
- `duration_ns`
  - 单次 hook 的近似耗时

这些字段共同描述一条访问事件：

- 主体是谁
- 请求了什么权限
- 访问的是哪个 inode / 哪类对象
- hook 返回了什么
- 这次检查大致花了多久

## 阶段划分

为了让输出更适合分析，项目把事件划分为三个阶段：

- `path_walk`
  - 主要对应目录遍历过程中的检查
- `open`
  - 主要对应打开文件时的检查
- `io`
  - 主要对应打开文件后的读写类权限检查

当前判定规则为：

- `selinux_inode_permission`
  - `mask` 带 `MAY_OPEN` 时记为 `open`
  - 目录上的纯 `MAY_EXEC` 记为 `path_walk`
  - 其他情况记为 `inode`
- `selinux_file_open`
  - 固定记为 `open`
- `selinux_file_permission`
  - 固定记为 `io`

## 返回值分析

项目重点保留了 hook 的返回值及其解释，便于从“参数”走到“结果”。

- `ret`
  - hook 的原始返回值
- `runtime_result`
  - 运行时结果，如 `allow` / `deny`
- `policy_result`
  - 对策略层含义的保守解释

这使得我们可以区分：

- 明确拒绝
- 特殊返回路径
- 允许但仍需结合上下文解释的情况

例如：

- `ret == -EACCES`
  - 更接近真实的拒绝事件
- `ret == -ECHILD`
  - 更可能是 `MAY_NOT_BLOCK` / RCU 路径下的特殊返回
- `ret == 0`
  - 说明本次 hook 未返回错误，但不能单靠这几个 hook 断言完整策略语义

## 已实现的分析规则

`analyze_events.py` 目前内置了几类可解释规则：

- `selinux_deny`
  - 运行时直接拒绝访问
- `may_not_block_echild`
  - 命中 `-ECHILD` 特殊路径
- `fd_use_without_open_snapshot`
  - 看到了 `file_permission`，但当前采集窗口里没有匹配的 `file_open`
- `deep_path_walk`
  - 同一线程的 `path_walk` 次数过多
- `wide_directory_scan`
  - 同一线程触达了较多不同目录 inode
- `slow_file_permission_tail`
  - `selinux_file_permission` 的高分位耗时偏高

这些规则不是最终结论，而是对事件流的第一层解释，适合做项目展示和后续扩展。

## 构建

默认使用当前系统的 kernel build 目录：

```bash
cd ./lsm-hook-analysis
make
```

如果需要手动指定内核构建目录：

```bash
make KDIR=/path/to/kernel/build
```

如果使用一棵尚未准备好的标准内核源码树，需要先完成：

```bash
make olddefconfig
make modules_prepare
```

## 运行方式

先确保 `debugfs` 已挂载：

```bash
mount -t debugfs none /sys/kernel/debug
```

加载模块：

```bash
insmod lsm_hook_analysis.ko
```

查看统计信息：

```bash
cat /sys/kernel/debug/lsm_hook_analysis/stats
```

导出事件：

```bash
cat /sys/kernel/debug/lsm_hook_analysis/events
```

清空事件缓存：

```bash
echo clear > /sys/kernel/debug/lsm_hook_analysis/control
```

关闭或恢复采集：

```bash
echo enable=0 > /sys/kernel/debug/lsm_hook_analysis/control
echo enable=1 > /sys/kernel/debug/lsm_hook_analysis/control
```

把事件流直接送入分析器：

```bash
cat /sys/kernel/debug/lsm_hook_analysis/events | python3 analyze_events.py
```

也可以先保存后再分析：

```bash
cat /sys/kernel/debug/lsm_hook_analysis/events > events.jsonl
python3 analyze_events.py events.jsonl
```

## Mock 数据与离线演示

如果当前环境不方便加载内核模块，可以直接使用 `mock-data/` 中的样例数据演示分析流程：

```bash
cd ./lsm-hook-analysis
python3 run_mock_tests.py
```

当前包含四类样例：

- `normal_access.jsonl`
  - 正常访问链路
- `deny_access.jsonl`
  - 明确拒绝访问
- `echild_special.jsonl`
  - `-ECHILD` 特殊返回
- `scan_and_slow_io.jsonl`
  - 深路径遍历、目录扫描、缺失 open 快照和慢 I/O 检查

单独分析某个样例：

```bash
python3 analyze_events.py mock-data/deny_access.jsonl
python3 analyze_events.py mock-data/scan_and_slow_io.jsonl
```

## 输出示例

事件样例：

```json
{"seq":1,"ts_ns":123456789,"duration_ns":24130,"subject":{"tgid":4321,"tid":4321,"comm":"cat","secid":123,"scontext":"system_u:system_r:unconfined_t:s0"},"request":{"hook":"selinux_inode_permission","phase":"path_walk","mask_raw":1,"file_flags":0,"perm":"search"},"target":{"dev":"dm-0","ino":234567,"type":"dir","tclass":"dir","tcontext":"system_u:object_r:etc_t:s0"},"path":{"path":"/etc","note":"alias_path_non_unique"},"result":{"ret":0,"runtime_result":"allow","policy_result":"unknown_if_permissive"}}
```

分析结果样例：

```text
events=25
findings=2
[high] selinux_deny: SELinux 在运行时拒绝访问: pid=4321/4321 comm=cat hook=selinux_file_open phase=open perm=open,read target=dm-0:345678(reg) path=/secret.txt ret=-13
[medium] fd_use_without_open_snapshot: 观察到 file_permission 但当前输入流里没有匹配到 file_open，可能是继承/传递 fd，也可能是采集窗口不完整: pid=5000/5000 comm=python hook=selinux_file_permission phase=io perm=write target=dm-0:456789(reg) path=/tmp/output.log ret=0
```

## 项目特点

这个项目更像一个“可解释分析原型”，它的特点是：

- 只关注少量关键 hook，范围可控
- 保留参数、返回值和耗时，便于解释
- 输出为 JSONL，方便后处理
- 不侵入现有内核源码树，适合实验和课程场景

## 局限性

当前版本仍有一些明确边界：

- `inode_permission` 的路径恢复依赖 inode alias，不能保证是唯一完整路径
- `dev + ino + type` 比单一路径更适合作为对象标识
- `tclass` 是基于 inode 类型映射得到的，不是直接读取 SELinux 内部 `sclass`
- `ret == 0` 时，无法仅凭这三个 hook 断言完整策略结果
- 还没有直接显式标出 `selinux_file_permission` 是否命中内部 fast path


## 总结

`lsm-hook-analysis` 的核心价值，是把 SELinux LSM hook 的“参数输入”和“返回结果”连接起来，并以结构化、可解释、可演示的方式呈现出来。
