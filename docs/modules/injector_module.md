# `lha_centos9_injector.ko` 模块说明

## 1. 模块职责

`lha_centos9_injector.ko` 是一个仅用于自测的调试模块，不参与真实生产抓取链路。

它的作用是：

- 创建 debugfs 调试入口
- 构造 3 组固定样例事件
- 调用 resolver 导出 API 完成解析和 JSON 格式化
- 保存最近一次生成的 JSON，便于人工检查

它依赖 `lha_centos9_resolver.ko`，模块里也通过 `MODULE_SOFTDEP("pre: lha_centos9_resolver")` 声明了这一点。

## 2. debugfs 接口

加载成功后，injector 会创建目录：

- `/sys/kernel/debug/lha_centos9`

目录下包含两个文件：

- `inject`
  只写文件，用于触发样例事件
- `last_json`
  只读文件，用于读取最近一次解析输出

初始化后，如果还没有执行过注入，`last_json` 的默认内容是：

```json
{"status":"no event injected yet"}
```

## 3. 支持的注入命令

向 `inject` 写入以下命令之一即可触发对应样例：

- `sample_inode`
- `sample_open`
- `sample_append`

写入其他字符串会返回 `-EINVAL`。

## 4. 三组样例的真实行为

### 4.1 `sample_inode`

该样例会：

- 用 `kern_path("/tmp", LOOKUP_FOLLOW, &path)` 找到 `/tmp`
- 对应 `inode` 调用 `igrab()`
- 构造 `LHA_HOOK_INODE_PERMISSION`
- 设置 `ret = 0`
- 设置 `mask = LHA_MAY_EXEC`

它主要用于验证：

- inode 目标解析
- `search/exec` 权限语义解码
- inode 路径 best effort 恢复

### 4.2 `sample_open`

该样例会：

- 用 `filp_open("/etc/hosts", O_RDONLY, 0)` 打开文件
- 构造 `LHA_HOOK_FILE_OPEN`
- 设置 `ret = 0`

它主要用于验证：

- `file_open` 路径恢复
- 基于 `f_flags` 的 `open|read` 权限解码

### 4.3 `sample_append`

该样例会：

- 用 `filp_open("/tmp/lha_inject.log", O_CREAT | O_WRONLY | O_APPEND, 0600)` 打开文件
- 构造 `LHA_HOOK_FILE_PERMISSION`
- 设置 `ret = -EACCES`
- 设置 `mask = LHA_MAY_WRITE`

它还会额外执行一段“匹配 AVC deny 注入”逻辑：

1. 先调用一次 `lha_centos9_resolve_event()` 得到完整解析结果。
2. 用这条结果构造一条完全匹配的 `struct lha_avc_event_v1`。
3. 调用 `lha_centos9_record_avc_event()` 把 deny 写进 resolver 缓存。
4. 再次调用 `lha_centos9_resolve_event()`，让最终 `policy_result` 命中 `deny`。

因此这个样例主要用于验证：

- `file_permission` 事件解析
- `O_APPEND` 对 `append` 权限输出的影响
- resolver 内置 AVC 关联逻辑

## 5. 引用管理

injector 会自己为样例事件建立并释放稳定引用：

- `task`
  直接取 `current`，并调用 `get_task_struct(current)`
- `cred`
  调用 `get_current_cred()`
- `inode`
  通过 `igrab()` 获取引用
- `file`
  通过 `filp_open()` 返回的 `struct file *` 持有引用

样例处理完成后，injector 内部会调用自己的 `lha_release_capture_refs()` 释放这些引用。

这个释放函数是模块内部 `static` 函数，没有导出给其他模块使用。

## 6. 运行要求

使用 injector 前需要：

- 已加载 `lha_centos9_resolver.ko`
- 已挂载 debugfs
- 当前系统允许访问样例里用到的路径，例如 `/tmp`、`/etc/hosts`

典型顺序：

```bash
cd kmod
make
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko
sudo mount -t debugfs none /sys/kernel/debug
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

## 7. 使用边界

injector 只适合：

- 验证 resolver 是否能正常工作
- 快速观察 JSON 输出结构
- 验证 AVC deny 关联链路

它不代表：

- 真实系统发生过一次 SELinux hook 拦截
- 真实生产抓取模块的接入方式
- 真实业务流量下的时序和并发行为

## 8. 失败场景

常见失败原因包括：

- debugfs 未挂载，导致看不到 `/sys/kernel/debug/lha_centos9`
- 未先加载 resolver，导致 injector 无法正常依赖导出符号
- 样例路径不存在或无法打开
- resolver 本身解析失败

如果注入命令写入成功但没有期望输出，优先检查：

- `dmesg`
- `lsmod | grep lha`
- `/sys/kernel/debug/lha_centos9/last_json`
