# Resolver API 接入说明

本文档面向“外部抓取模块”作者，说明在拿到 `task/cred/inode/file/mask/ret` 后，如何调用 `lsm-hook-analysis` 提供的内核态 resolver 接口。

## 1. 适用范围

当前 `kmod/` 版本只支持以下 3 个 SELinux hook 事件：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

外部模块负责：

- 在 hook 现场抓取参数和返回值
- 在 hook 现场保存稳定引用
- 将原始事件异步交给 resolver

resolver 负责：

- 根据 `hook_id` 路由解析
- 从 `task/cred/inode/file` 解析主体、目标和权限语义
- 生成统一结构化结果
- 按需格式化成 JSON

## 2. 对外接口

头文件位置：

- `kmod/lha_centos9_resolver.h`

导出符号：

- `lha_centos9_resolve_event()`
- `lha_centos9_format_json()`

实现位置：

- `kmod/lha_centos9_resolver.h:25-111`
- `kmod/lha_centos9_resolver.c`

接口定义如下：

```c
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out);

int lha_centos9_format_json(const struct lha_enriched_event_v1 *event,
			    char *buf,
			    size_t buf_len);
```

注意：

- 这两个符号通过 `EXPORT_SYMBOL_GPL` 导出，调用方模块需要是 GPL 兼容模块。
- `lha_centos9_resolve_event()` 成功返回 `0`，失败返回负错误码。
- `lha_centos9_format_json()` 在当前内核模块实现里成功返回 `0`，失败返回负错误码。
- `lha_centos9_resolver.ko` 是生产可用的 resolver API 模块。
- `lha_centos9_injector.ko` 只是可选的 debugfs 假事件注入/自测模块，也通过这两个导出 API 调用 resolver。

## 3. 输入输出结构

输入结构：`struct lha_capture_event_v1`

- `version`
  当前固定填 `1`
- `hook_id`
  3 种 hook 中的一种
- `ts_ns`
  事件时间戳，建议使用 ns 级时间
- `ret`
  hook 最终返回值
- `subject.task`
  hook 现场任务的稳定引用
- `subject.cred`
  hook 现场 cred 的稳定引用
- `args`
  对应 hook 的原始参数

输出结构：`struct lha_enriched_event_v1`

- `hook/hook_signature`
- `subject`
- `request`
- `target`
- `result`

定义位置：

- `kmod/lha_centos9_resolver.h:25-93`

## 4. 推荐调用方式

不建议在原始 hook 回调里直接调用 resolver。

原因是 resolver 内部会调用：

- `security_secid_to_secctx()`
- `security_inode_getsecctx()`
- `d_path()`

这些操作都可能睡眠，因此推荐在可睡眠上下文中执行，例如：

- `workqueue`
- `kthread`

推荐链路如下：

1. hook 现场抓到 `task/cred/inode/file/mask/ret`
2. 在 hook 现场为这些对象建立稳定引用
3. 组装 `struct lha_capture_event_v1`
4. 将事件放入工作队列
5. 在 worker 中调用 `lha_centos9_resolve_event()`
6. 如需字符串结果，再调用 `lha_centos9_format_json()`
7. 调用方释放此前建立的引用

相关实现位置：

- 可睡眠上下文要求：`kmod/lha_centos9_resolver.h:95-105`
- 路由入口：`kmod/lha_centos9_resolver.c`
- JSON 输出：`kmod/lha_centos9_resolver.c`

## 5. 稳定引用要求

外部抓取方必须在 hook 现场建立稳定引用，再把这些对象传给 resolver。

常见做法：

- `task`：`get_task_struct()`
- `cred`：`get_cred()` 或 `get_current_cred()`
- `inode`：`igrab()` 或 `ihold()`
- `file`：`get_file()`

用完后需要由调用方自己释放：

- `task`：`put_task_struct()`
- `cred`：`put_cred()`
- `inode`：`iput()`
- `file`：`fput()`

注意：

- `kmod/lha_centos9_injector.c` 中虽然有 `lha_release_capture_refs()`，但它是 injector 模块内部的 `static` 函数，没有导出，外部模块不能直接调用。
- 调用方需要自行实现一份对应的释放逻辑。

相关实现位置：

- 建立引用约束：`kmod/lha_centos9_resolver.h:95-100`
- 内部释放逻辑参考：`kmod/lha_centos9_injector.c`

## 6. 三类 hook 的填写方式

### 6.1 inode_permission

```c
event.version = 1;
event.hook_id = LHA_HOOK_INODE_PERMISSION;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

event.args.inode_permission.inode = igrab(inode);
event.args.inode_permission.mask = mask;
```

### 6.2 file_open

```c
event.version = 1;
event.hook_id = LHA_HOOK_FILE_OPEN;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

get_file(file);
event.args.file_open.file = file;
```

### 6.3 file_permission

```c
event.version = 1;
event.hook_id = LHA_HOOK_FILE_PERMISSION;
event.ts_ns = ktime_get_real_ns();
event.ret = ret;

event.subject.task = task;
get_task_struct(task);

event.subject.cred = get_cred(cred);

get_file(file);
event.args.file_permission.file = file;
event.args.file_permission.mask = mask;
```

注意：

- `file_open` 没有 `mask` 参数。
- `version` 必须是 `1`，否则 `lha_centos9_resolve_event()` 会返回 `-EINVAL`。
- `subject.task` 和 `subject.cred` 不能为空，否则 `lha_centos9_resolve_event()` 会返回 `-EINVAL`。

相关实现位置：

- 参数校验：`kmod/lha_centos9_resolver.c`
- hook 路由：`kmod/lha_centos9_resolver.c`

## 7. 最小接入示例

下面给出一个“外部抓取模块”在 worker 中调用 resolver 的最小示例。示例以 `file_permission` 为例，其他两类 hook 只需要按上面的字段填写方式替换输入参数即可。

```c
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/cred.h>
#include <linux/fs.h>

#include "lha_centos9_resolver.h"

struct my_pending_event {
	struct work_struct work;
	struct lha_capture_event_v1 ev;
};

static struct workqueue_struct *my_wq;

static void my_release_capture_refs(struct lha_capture_event_v1 *ev)
{
	switch (ev->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		if (ev->args.inode_permission.inode)
			iput(ev->args.inode_permission.inode);
		break;
	case LHA_HOOK_FILE_OPEN:
		if (ev->args.file_open.file)
			fput(ev->args.file_open.file);
		break;
	case LHA_HOOK_FILE_PERMISSION:
		if (ev->args.file_permission.file)
			fput(ev->args.file_permission.file);
		break;
	default:
		break;
	}

	if (ev->subject.task)
		put_task_struct(ev->subject.task);
	if (ev->subject.cred)
		put_cred(ev->subject.cred);
}

static void my_resolve_worker(struct work_struct *work)
{
	struct my_pending_event *p =
		container_of(work, struct my_pending_event, work);
	struct lha_enriched_event_v1 out;
	char json[8192];
	int rc;

	rc = lha_centos9_resolve_event(&p->ev, &out);
	if (!rc) {
		rc = lha_centos9_format_json(&out, json, sizeof(json));
		if (!rc)
			pr_info("resolved event: %s\n", json);
	}

	my_release_capture_refs(&p->ev);
	kfree(p);
}

static void capture_file_permission_event(struct task_struct *task,
					  const struct cred *cred,
					  struct file *file,
					  int mask,
					  int ret)
{
	struct my_pending_event *p;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return;

	INIT_WORK(&p->work, my_resolve_worker);

	p->ev.version = 1;
	p->ev.hook_id = LHA_HOOK_FILE_PERMISSION;
	p->ev.ts_ns = ktime_get_real_ns();
	p->ev.ret = ret;

	p->ev.subject.task = task;
	get_task_struct(task);

	p->ev.subject.cred = get_cred(cred);

	get_file(file);
	p->ev.args.file_permission.file = file;
	p->ev.args.file_permission.mask = mask;

	queue_work(my_wq, &p->work);
}
```

## 8. 解析结果的使用方式

### 8.1 结构化结果

如果调用方只需要结构化字段，可以直接使用：

```c
struct lha_enriched_event_v1 out;
int rc;

rc = lha_centos9_resolve_event(&event, &out);
if (!rc) {
	/* 直接读取 out.subject / out.request / out.target / out.result */
}
```

### 8.2 JSON 结果

如果调用方需要字符串结果，可以继续调用：

```c
char json[8192];
int rc;

rc = lha_centos9_format_json(&out, json, sizeof(json));
if (!rc) {
	/* 将 json 输出到 debugfs/procfs/netlink/trace buffer 等通道 */
}
```

## 9. 常见注意事项

- 不要把裸 `task/cred/inode/file` 指针直接异步传给 worker 而不加引用。
- 不要在不可睡眠上下文直接调用 resolver。
- `inode_permission` 只有 `inode`，路径恢复是 best effort，不保证是全局绝对路径。
- `file_open/file_permission` 因为持有 `file->f_path`，通常更容易恢复出接近真实访问路径的结果。
- 当前 `policy_result` 需要调用方在 `struct lha_capture_event_v1.policy_state` 中显式提供；未提供时会回退为 `unknown`。
- 如果调用方与 resolver 模块分开加载，推荐先加载 `lha_centos9_resolver.ko`，再加载抓取模块。

相关实现位置：

- `policy_result` 当前行为：`kmod/lha_centos9_resolver.c`
- `file` 路径恢复：`kmod/lha_centos9_resolver.c`
- `inode` 路径恢复：`kmod/lha_centos9_resolver.c`
- debugfs 假事件注入参考：`kmod/lha_centos9_injector.c`

## 10. 推荐阅读

- `docs/interface_contract.md`
- `docs/centos_stream9_runtime.md`
- `kmod/lha_centos9_resolver.h`
- `kmod/lha_centos9_resolver.c`
- `kmod/lha_centos9_injector.c`
