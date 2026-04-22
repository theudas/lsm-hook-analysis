# CentOS Stream 9 运行说明

## 1. 代码运行在什么地方

这套代码分成两层：

- `include/` + `src/` + `tests/`
  这是当前已经跑通的“解析框架层”，主要用于把事件模型、hook 路由、权限语义解码和 JSON 格式定下来。
- `kmod/`
  这是面向 CentOS Stream 9 的“内核运行层”，它才是实际部署到服务器上的版本。

真正部署时，关键逻辑运行在 **内核态**，而不是用户态。

更准确地说：

1. 外部抓取方在 SELinux hook 现场拿到：
   - hook 类型
   - hook 参数
   - hook 返回值
   - 时间戳
2. 抓取方把这些原始输入交给 resolver
3. resolver 在 **内核工作线程 / workqueue / kthread** 里继续解析：
   - `current`
   - `current_cred()`
   - `inode` / `file`
   - `scontext`
   - `tcontext`
   - 路径
4. 解析后的事件再被格式化成 JSON，或者作为结构化数据继续往外送

因此，这份代码不是“用户态命令行工具”，而是：

- 一个内核模块内的解析组件
- 或者一个和现有抓取模块链接在一起的内核侧库

## 2. 为什么建议在 workqueue 里运行

`kmod/lha_centos9_resolver.c` 这版实现默认建议在 **可睡眠上下文** 中运行，而不是直接塞进原始 hook 回调里。

原因是下面这些操作都可能睡眠或分配内存：

- `security_secid_to_secctx()`
- `security_inode_getsecctx()`
- `d_path()`
- `kmalloc(GFP_KERNEL)`

所以推荐工作流不是：

- hook 里直接把所有字段都解析完

而是：

1. hook 现场只抓最小必要输入
2. 把输入放到队列中
3. 用 workqueue 异步调用 `lha_centos9_resolve_event()`

这也是为什么文档里一直把 resolver 定义为“hook 之后运行”。

## 3. 为什么这版可以适配 CentOS Stream 9

这版 `kmod/` 代码尽量使用 **公开 LSM 接口**，避免强依赖 SELinux 私有内部符号：

- 主体 secid:
  `security_cred_getsecid(current_cred(), &secid)`
- 主体 context:
  `security_secid_to_secctx(secid, &secctx, &len)`
- 目标 context:
  `security_inode_getsecctx(inode, &ctx, &len)`
- context 释放:
  `security_release_secctx()`

这些接口在 `centos-stream-9/security/security.c` 中是导出的，适合普通外部模块使用。

相对地，下面这些更偏 SELinux 内部实现的符号并没有被本版当作硬依赖：

- `cred_sid()`
- `security_sid_to_context(&selinux_state, ...)`
- `selinux_inode()`
- `selinux_state`

这样做的目的是让 resolver 更容易作为外部模块部署到你的 CentOS Stream 9 服务器上。

## 4. 当前内核模块代码做了什么

`kmod/lha_centos9_resolver.c` 已经实现了：

- 3 个 hook 的路由
- 从 `current` 读取 `pid/tid/comm`
- 从 `current_cred()` 读取主体 secid，再转成 `scontext`
- 从 `inode` / `file` 读取：
  - `dev`
  - `ino`
  - `type`
  - `path`
- 从 `security_inode_getsecctx()` 读取 `tcontext`
- 从 `inode->i_mode` 解码：
  - `obj_type`
  - `type`
  - `tclass`
  - `perm`
- 生成统一结构化结果
- 将结果格式化成 JSON

## 5. 路径字段的现实边界

`path` 字段分两种情况：

- 对 `file *`
  可以通过 `d_path(&file->f_path, ...)` 尽量恢复绝对路径
- 对 `inode *`
  因为只有 inode，没有 mount/path 上下文，无法保证拿到全局绝对路径
  这时只能 best effort：
  - 先尝试 `d_find_alias(inode)` + `dentry_path_raw()`
  - 如果还是不行，至少退化成文件名或 `<unknown>`

所以：

- `file_open` / `file_permission` 通常更容易拿到绝对路径
- `inode_permission` 只能尽力恢复

## 6. 代码如何运行

### 6.1 编译方式

在服务器上，推荐使用运行中内核对应的构建目录：

```bash
cd /path/to/lsm-hook-analysis/kmod
make -C /lib/modules/$(uname -r)/build M=$PWD modules
```

如果你是基于本地这棵 `centos-stream-9` 源码树做开发，也可以：

```bash
cd /Users/tanruoying/Desktop/codex_chat/lsm-hook-analysis/kmod
make KDIR=/Users/tanruoying/Desktop/codex_chat/centos-stream-9
```

前提是对应内核树已经完成模块编译所需的准备工作。

### 6.2 加载方式

编译出 `lha_centos9_resolver.ko` 后：

```bash
sudo insmod lha_centos9_resolver.ko
```

如果你的抓取模块和 resolver 是分开的，那么典型加载顺序是：

1. 先加载 `lha_centos9_resolver.ko`
2. 再加载抓取 hook 参数/返回值的模块
3. 抓取模块在收到原始事件后调用：
   `lha_centos9_resolve_event()`

### 6.3 推荐调用方式

最推荐的方式不是在 hook 原地调用，而是：

1. hook 现场组装 `struct lha_capture_event_v1`
2. 把它丢进工作队列
3. worker 中调用：
   `lha_centos9_resolve_event()`
4. 再调用：
   `lha_centos9_format_json()`
5. 把 JSON 写到你自己的输出通道

输出通道可以是：

- debugfs
- procfs
- relayfs
- netlink
- character device
- trace buffer

## 7. 当前还没完全解决的点

当前 `kmod/` 版本还保留一个明确未完成字段：

- `policy_result`

现在仍然默认输出：

- `unknown`

原因很简单：

- `ret` 只能告诉你运行时结果
- 不能可靠代表 permissive 模式下的真实策略判定

所以当前内核模块已经可以比较完整地得到：

- `subject`
- `request`
- `target`
- `ret`
- `runtime_result`

但 `policy_result` 还需要后续单独补策略判定路径。

## 8. 你现在应该怎么理解整个项目

当前项目里：

- `src/` 是“框架版参考实现”
- `kmod/` 是“真正准备跑在 CentOS Stream 9 服务器上的实现方向”

如果你的目标是服务器实际部署，那么后续主要应继续推进 `kmod/` 目录，而不是把 `src/` 当成最终运行形态。
