# lsm-hook-analysis

`lsm-hook-analysis` 当前包含一套可编译的核心解析层：

- 统一输入结构 `lha_capture_event_v1`
- 统一输出结构 `lha_enriched_event_v1`
- 3 个 SELinux hook 的路由与解析逻辑
- `mask` 到权限语义的解码
- JSON 序列化
- `kernel ops` 适配接口
- CentOS Stream 9 下拆分的 2 个内核模块：
  - `lha_centos9_resolver.ko`
    生产可用的 resolver API 模块
  - `lha_centos9_injector.ko`
    仅用于 debugfs 假事件注入和自测的测试模块

这层代码默认不直接耦合具体内核头文件，而是通过 `kernel ops` 回调接入真实内核态取数逻辑。这样我们可以先把事件模型、路由和输出层稳定下来，再把真正的 `current`、`cred`、`inode`、`file`、SELinux context 解析接进去。

## 当前支持的 hook

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

## 目录结构

- `include/`
  公共头文件
- `src/`
  核心实现
- `tests/`
  用户态单元测试
- `docs/`
  文档

## 构建

```bash
make
```

## 测试

```bash
make test
```

测试使用一组 mock `kernel ops`，验证：

- hook 路由
- subject/request/target/result 填充
- `perm` 解码
- JSON 输出

## 下一步

下一步需要补的是真正的内核接入层，也就是：

- 从外部稳定保存下来的 `task/cred` 读取 `pid/tid/comm/scontext`
- 从外部传入的 `inode` / `file` 读取目标对象信息
- 从 SELinux/LSM 可用接口读取 `tcontext`
- 尽力恢复路径
