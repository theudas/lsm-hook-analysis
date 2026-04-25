# lsm-hook-analysis

`lsm-hook-analysis` 是一个面向 SELinux LSM hook 事件的内核态资源访问解析项目。它不直接抓取 hook，而是接收外部抓取模块传入的 `task/cred/inode/file/mask/ret` 等内核对象和结果，在内核态解析出主体、目标资源、访问权限、SELinux 上下文、路径和运行结果，并输出统一结构化事件或 JSON。

当前仓库只保留 CentOS Stream 9 相关的内核态实现，用户态原型、测试和回放工具已移除。

## 当前能力

当前支持 3 类 SELinux hook 事件：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

当前可以解析和输出：

- 主体信息：`pid`、`tid`、`comm`、`scontext`
- 请求信息：`mask_raw`、`obj_type`、`perm`
- 目标资源：`dev`、`ino`、`type`、`path`、`tclass`、`tcontext`
- 结果信息：`ret`、`runtime_result`、`policy_result`
- JSON 格式化结果
- 内核态 AVC 关联结果：`deny`、`inferred_allow` 或 `unknown`

## 模块结构

- `kmod/lha_centos9_resolver.c`
  生产可用的 CentOS Stream 9 内核态 resolver 模块。
- `kmod/lha_centos9_injector.c`
  仅用于 debugfs 假事件注入和自测的独立测试模块。
- `kmod/lha_centos9_resolver.h`
  外部抓取模块接入时使用的结构体和导出 API。
- `docs/`
  接口、运行和使用文档。

`kmod/` 会构建出两个内核模块：

- `lha_centos9_resolver.ko`
  生产模块，导出 `lha_centos9_resolve_event()`、`lha_centos9_format_json()` 和 AVC 关联辅助 API。
- `lha_centos9_injector.ko`
  自测模块，通过 resolver 导出的 API 构造假事件并输出最近一次 JSON。

## 快速开始

内核模块编译和运行需要在 Linux/CentOS Stream 9 环境中进行：

```bash
cd kmod
make
sudo insmod lha_centos9_resolver.ko
sudo insmod lha_centos9_injector.ko
```

假事件注入自测：

```bash
sudo mount -t debugfs none /sys/kernel/debug
echo sample_open | sudo tee /sys/kernel/debug/lha_centos9/inject
cat /sys/kernel/debug/lha_centos9/last_json
```

完整步骤请看：

- `docs/usage.md`

## 对外接入方式

外部抓取模块需要：

1. 在 hook 现场保存稳定引用，例如 `get_task_struct()`、`get_cred()`、`get_file()`、`igrab()`。
2. 组装 `struct lha_capture_event_v1`。
3. 在 workqueue/kthread 等可睡眠上下文中调用 `lha_centos9_resolve_event()`。
4. 如需 JSON，再调用 `lha_centos9_format_json()`。
5. 如需基于 AVC deny 判定 `policy_result`，再调用 `lha_centos9_apply_avc_policy_result()`。
6. 调用方自己释放此前保存的引用。

详细 API 说明请看：

- `docs/api.md`

## 重要边界

- 本项目当前不负责注册或抓取真实 LSM hook。
- 真实生产链路需要外部抓取模块把 hook 参数和返回值传给 resolver。
- 真实生产链路还需要外部来源提供 AVC 事件，再交给 resolver 侧做关联。
- `file *` 路径恢复通常更接近用户空间看到的真实路径。
- `inode *` 路径恢复是 best effort，不保证是全局绝对路径。
- `lha_centos9_injector.ko` 只是自测模块，不建议作为生产入口。

## 文档

- `docs/usage.md`
  从克隆项目到编译、加载模块、假事件注入的完整操作说明。
- `docs/api.md`
  外部模块如何调用 resolver API。
- `docs/interface_contract.md`
  v1 输入输出接口约束。
- `docs/centos_stream9_runtime.md`
  CentOS Stream 9 内核态运行说明。
