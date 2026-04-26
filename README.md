# lsm-hook-analysis

`lsm-hook-analysis` 是一个面向 SELinux LSM hook 事件的内核态解析项目。它不直接抓取 hook，而是接收外部模块传入的 `task/cred/inode/file/mask/ret` 等对象，在可睡眠内核上下文中补齐主体、目标资源、权限语义、SELinux 上下文和结果信息，再输出统一结构体或 JSON。

当前仓库只保留 CentOS Stream 9 相关的内核模块实现。

## 当前支持范围

当前只支持以下 3 类 hook 输入：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

当前可输出的主要字段包括：

- `subject`
  `pid`、`tid`、`comm`、`scontext`
- `request`
  `mask_raw`、`obj_type`、`perm`
- `target`
  `dev`、`ino`、`type`、`path`、`tclass`、`tcontext`
- `result`
  `ret`、`runtime_result`、`policy_result`

其中：

- `runtime_result` 当前按 `ret == 0`、`ret == -EACCES`、其他错误三类输出为 `allow`、`deny`、`error`
- `policy_result` 当前主路径依赖 resolver 内部 AVC deny 关联，实际输出为 `deny`、`inferred_allow` 或 `unknown`

## 模块组成

`kmod/` 当前会构建 3 个模块：

- `lha_centos9_resolver.ko`
  核心解析模块，提供事件解析、JSON 格式化和 AVC 关联辅助接口
- `lha_centos9_injector.ko`
  debugfs 自测模块，用固定样例事件验证 resolver 行为
- `lha_centos9_avc_capture.ko`
  AVC deny 抓取模块，把 `selinux_audited` tracepoint 事件写入 resolver 缓存

公共头文件是：

- `kmod/lha_centos9_resolver.h`

## 快速开始

模块编译和加载需要在 Linux 环境中完成，并且应使用目标运行内核对应的模块构建目录。

```bash
cd kmod
make
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko
sudo mount -t debugfs none /sys/kernel/debug
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

完整操作见 [docs/usage_guide.md](docs/usage_guide.md)。

## 生产接入方式

生产链路中的典型调用顺序是：

1. 外部抓取模块在 hook 现场保存稳定引用，例如 `get_task_struct()`、`get_cred()`、`igrab()`、`get_file()`。
2. 组装 `struct lha_capture_event_v1`。
3. 在 `workqueue` 或 `kthread` 中调用 `lha_centos9_resolve_event()`。
4. 如需 JSON，再调用 `lha_centos9_format_json()`。
5. 如需 AVC deny 关联，加载 `lha_centos9_avc_capture.ko`，或由外部模块调用 `lha_centos9_record_avc_event()`。
6. 调用方负责释放之前建立的对象引用。

接入细节见 [docs/resolver_api_access_guide.md](docs/resolver_api_access_guide.md)。

## 关键边界

- 本项目当前不负责注册或抓取真实 LSM hook。
- resolver 设计为运行在可睡眠上下文中，不建议直接在原始 hook 回调中调用。
- `file *` 路径恢复通常更完整；`inode *` 路径恢复是 best effort。
- 当前内置 AVC 关联只能稳定表达 deny 证据及其缺失，不能给出强语义的策略 `allow`。
- `lha_centos9_injector.ko` 仅用于自测，不是生产入口。

## 文档

- [docs/usage_guide.md](docs/usage_guide.md)
  编译、加载、卸载和 injector 自测步骤
- [docs/resolver_api_access_guide.md](docs/resolver_api_access_guide.md)
  外部模块接入 resolver 的 API 和调用方式
- [docs/interface_contract.md](docs/interface_contract.md)
  输入输出结构、字段语义和返回约束
- [docs/centos_stream9_runtime.md](docs/centos_stream9_runtime.md)
  CentOS Stream 9 运行前提和运行边界
- [docs/resolver_output_architecture_design.md](docs/resolver_output_architecture_design.md)
  resolver 输出分层、接口设计和生产级演进方案
- [docs/modules/resolver_module.md](docs/modules/resolver_module.md)
  resolver 模块详细说明
- [docs/modules/injector_module.md](docs/modules/injector_module.md)
  injector 模块详细说明
- [docs/modules/avc_capture_module.md](docs/modules/avc_capture_module.md)
  AVC capture 模块详细说明
