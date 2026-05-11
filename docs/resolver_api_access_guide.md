# Resolver API 接入说明

本文档面向外部抓取模块作者，说明当前仓库中真实可用的 resolver 接口、推荐调用顺序和 AVC 关联方式。

注意：当前代码语义已经更新为：

- `lha_centos9_resolve_event()` 在成功返回前，会自动尝试把解析结果送入已注册的 `event_channel`
- 如果 `lha_centos9_event_channel.ko` 未加载，解析本身仍然成功，只是不会进入连续事件流
- 少数内部场景如果只想解析、不想自动送流，可使用 `lha_centos9_resolve_event_no_submit()`

## 1. 适用范围

当前 API 只覆盖以下 3 类 SELinux hook 事件：

- `selinux_inode_permission(struct inode *inode, int mask)`
- `selinux_file_open(struct file *file)`
- `selinux_file_permission(struct file *file, int mask)`

resolver 的职责是：

- 接收外部模块采集到的 hook 参数和最终返回值
- 解析主体、目标对象、权限语义和 SELinux context
- 输出统一结构化结果
- 按需格式化 JSON
- 用内部 AVC 缓存补充 `policy_result`

## 2. 头文件与导出符号

头文件：

- `kmod/lha_centos9_resolver.h`

当前导出的 GPL 符号有：

- `lha_centos9_resolve_event()`
- `lha_centos9_resolve_event_no_submit()`
- `lha_centos9_format_json()`
- `lha_centos9_record_avc_event()`
- `lha_centos9_policy_result_kind_to_string()`
- `lha_centos9_correlate_avc_policy()`
- `lha_centos9_apply_avc_policy_result()`

最常见的外部接入只需要：

- `lha_centos9_resolve_event()`
- `lha_centos9_format_json()`
- 可选的 `lha_centos9_record_avc_event()`

如果要理解连续事件输出链路，还需要知道：

- `kmod/lha_centos9_event_channel.h`
- `lha_centos9_submit_event()`

但在当前代码语义下，普通生产调用方通常不需要自己显式调用 `lha_centos9_submit_event()`。

## 3. 推荐接入顺序

不建议在原始 hook 回调里直接调用 resolver。当前实现会调用可能睡眠的接口，因此建议在可睡眠上下文中处理。

推荐顺序如下：

1. hook 现场拿到 `task`、`cred`、`inode` 或 `file`、`mask`、`ret`。
2. 在 hook 现场为这些对象建立稳定引用。
3. 组装 `struct lha_capture_event_v1`。
4. 把事件放到 `workqueue` 或 `kthread`。
5. 在 worker 中调用 `lha_centos9_resolve_event()`。
6. `lha_centos9_resolve_event()` 成功返回前，会自动尝试把结果送到 `event_channel`。
7. 如需 JSON，再调用 `lha_centos9_format_json()`。
8. 调用方释放之前建立的引用。

这意味着：

- 如果已经加载 `lha_centos9_event_channel.ko`，并且用户态 `lha-eventd` 正在读 `/dev/lha_centos9_event_stream`，那么第 5 步成功后，事件通常会继续出现在日志文件里
- 如果 `event_channel` 没加载，`lha_centos9_resolve_event()` 仍然可以作为纯解析接口使用

## 4. 稳定引用要求

外部模块必须在 hook 现场建立稳定引用，不能把裸指针直接跨异步阶段传给 resolver。

常见做法：

- `task`：`get_task_struct()`
- `cred`：`get_cred()` 或 `get_current_cred()`
- `inode`：`igrab()` 或 `ihold()`
- `file`：`get_file()`

对应释放：

- `task`：`put_task_struct()`
- `cred`：`put_cred()`
- `inode`：`iput()`
- `file`：`fput()`

注意：仓库里的 `lha_centos9_injector.c` 虽然有内部释放函数，但它不是导出 API。

## 5. 三类输入的填写方式

### 5.1 `inode_permission`

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

### 5.2 `file_open`

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

### 5.3 `file_permission`

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

必须注意：

- `version` 必须为 `1`
- `subject.task` 和 `subject.cred` 不能为空
- `file_open` 没有单独的 `mask` 字段

## 6. 最小调用示例

下面是一个在 worker 中调用 resolver 的最小示例，示例只演示 `file_permission` 这一类输入。

```c
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "lha_centos9_resolver.h"

struct my_pending_event {
	struct work_struct work;
	struct lha_capture_event_v1 ev;
};

static void my_release_capture_refs(struct lha_capture_event_v1 *ev)
{
	if (ev->hook_id == LHA_HOOK_FILE_PERMISSION && ev->args.file_permission.file)
		fput(ev->args.file_permission.file);
	if (ev->subject.task)
		put_task_struct(ev->subject.task);
	if (ev->subject.cred)
		put_cred(ev->subject.cred);
}

static void my_worker(struct work_struct *work)
{
	struct my_pending_event *pending;
	struct lha_enriched_event_v1 out;
	char json[8192];
	int rc;

	pending = container_of(work, struct my_pending_event, work);

	rc = lha_centos9_resolve_event(&pending->ev, &out);
	if (!rc)
		rc = lha_centos9_format_json(&out, json, sizeof(json));

	my_release_capture_refs(&pending->ev);
	kfree(pending);
}

static int queue_capture_event(struct task_struct *task,
			       const struct cred *cred,
			       struct file *file,
			       int mask,
			       int ret)
{
	struct my_pending_event *pending;

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending)
		return -ENOMEM;

	INIT_WORK(&pending->work, my_worker);
	pending->ev.version = 1;
	pending->ev.hook_id = LHA_HOOK_FILE_PERMISSION;
	pending->ev.ts_ns = ktime_get_real_ns();
	pending->ev.ret = ret;
	pending->ev.subject.task = task;
	get_task_struct(task);
	pending->ev.subject.cred = get_cred(cred);
	get_file(file);
	pending->ev.args.file_permission.file = file;
	pending->ev.args.file_permission.mask = mask;

	schedule_work(&pending->work);
	return 0;
}
```

在当前代码语义下，这段示例已经具备两种效果：

- `out` 中拿到完整结构化结果
- 如果 `event_channel` 已加载，会自动把同一条结果送入连续事件流

如果某个内部流程只想解析、不想自动送流，可以改调：

```c
rc = lha_centos9_resolve_event_no_submit(&pending->ev, &out);
```

## 7. AVC deny 的两种接入方式

### 7.1 直接加载 AVC capture 模块

这是当前仓库内最省事的方式：

1. 加载 `lha_centos9_resolver.ko`
2. 加载 `lha_centos9_avc_capture.ko`
3. 让你的 hook 抓取模块继续只提交 hook 事件

此时 `lha_centos9_resolve_event()` 会在内部自动查询 resolver 缓存。

### 7.2 由你们自己的 AVC 模块写缓存

如果你们已经有自己的 AVC 采集链路，也可以自行构造：

```c
struct lha_avc_event_v1
```

然后调用：

```c
lha_centos9_record_avc_event(&event);
```

当前写入缓存时必须满足：

- `denied != 0`
- `scontext`、`tcontext`、`tclass`、`perm` 都非空

## 8. 当前关联行为

resolver 当前使用固定长度缓存和时间窗口进行 deny 匹配：

- 缓存长度：`128`
- 默认时间窗：`50 ms`

成功路径中，最终 `policy_result` 由缓存关联结果覆盖，当前只会输出：

- `deny`
- `inferred_allow`
- `unknown`

因此，如果你只调用 `lha_centos9_resolve_event()` 而从不向 resolver 写入 AVC deny，最终结果通常会是：

- 匹配键完整时 -> `inferred_allow`
- 匹配键不完整时 -> `unknown`

## 9. 返回值与缓冲区注意事项

- `lha_centos9_resolve_event()` 成功返回 `0`，失败返回负错误码
- 当前实现里，自动送流失败不会改变 `lha_centos9_resolve_event()` 的成功返回值
- `lha_centos9_format_json()` 对空参数会返回 `-EINVAL`
- 当前 `lha_centos9_format_json()` 不会把输出截断单独当作错误返回，调用方需要主动给足缓冲区

仓库中的 injector 使用 `8192` 字节 JSON 缓冲区，可作为参考。
