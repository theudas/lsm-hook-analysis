# 连续事件输出通道与用户态 logger 接口设计

本文档基于 [docs/resolver_output_architecture_design.md](/Users/tanruoying/Desktop/lsm-hook-analysis/docs/resolver_output_architecture_design.md) 第 7.4 节的推荐方向，定义生产链路中“连续事件输出通道 + 用户态 logger”的 v1 接口边界。

目标不是替换当前 `resolver`，而是在保留 `lha_centos9_resolve_event()` 现有职责的前提下，补上一条独立、可持续消费、可运维的输出链路。

## 1. 设计目标

- 保持 `resolver` 继续只产出 `lha_enriched_event_v1`
- 新增独立事件输出通道，不再依赖 `debugfs/last_json`
- 由用户态 `lha-eventd` 负责 JSON 序列化和文件落盘
- 内核态输出接口必须简单、低耦合、无目录/文件策略
- 用户态必须能感知顺序、背压和丢包

## 2. 默认假设

本设计先按以下前提收敛 v1：

- 事件只在本机内核态与本机用户态之间传递，不做跨主机传输
- 同一时刻只允许一个用户态 logger 独占消费
- 输出文件采用 NDJSON，即“一行一个 JSON 对象”
- 允许在用户态长期阻塞时发生丢包，但丢包必须可观测
- `injector + debugfs + last_json` 继续保留为开发/自测链路，不参与生产链路

如果后续需要多订阅者、远程传输、可靠重放或持久化队列，建议在 v1 之上单独演进，不要反向污染当前 `resolver` 接口。

## 3. 总体链路

当前代码已经落地成下面这条链路：

```text
外部 hook 抓取模块
    -> lha_centos9_resolve_event(in, &out)
    -> resolver 内部自动尝试 submit
    -> /dev/lha_centos9_event_stream
    -> lha-eventd
    -> /configured/log/dir/YYYY-MM-DD.log
```

职责划分如下：

- `resolver`
  只负责把 hook 现场输入解析成 `lha_enriched_event_v1`
- `event_channel`
  只负责把结构化事件稳定送到连续输出通道
- `lha-eventd`
  只负责读取、校验、序列化、按天落盘、flush/fsync、错误重试

需要特别说明：

- `lha_centos9_submit_event()` 仍然存在，并且仍然是 `event_channel` 的底层提交接口
- 但对普通生产调用方来说，当前实现已经把“自动送流”放进了 `lha_centos9_resolve_event()`
- 因此外部 hook 抓取模块通常只需要调用 `lha_centos9_resolve_event()`
- 如果某些内部流程只想解析、不想自动送流，则使用 `lha_centos9_resolve_event_no_submit()`

## 4. 内核态接口边界

### 4.1 保持不变的 resolver 接口

现有接口继续保留：

```c
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out);
```

当前实现中，这仍然是外部抓取模块获得统一结构化结果的主入口，而且它会在成功返回前自动尝试把结果送入 `event_channel`。

另外还新增了一个“只解析、不自动送流”的变体：

```c
int lha_centos9_resolve_event_no_submit(const struct lha_capture_event_v1 *in,
					struct lha_enriched_event_v1 *out);
```

它主要用于少数内部流程，例如：

- 需要先解析一次中间结果，再补 AVC，再重新解析
- 不希望第一次中间结果进入连续日志流

### 4.2 新增事件提交接口

底层事件提交通道仍保留以下接口：

- `kmod/lha_centos9_event_channel.h`

导出接口为：

```c
int lha_centos9_submit_event(const struct lha_enriched_event_v1 *event);
```

在当前代码里，它的定位是：

- `resolver` 自动送流时，最终会走到这层
- `event_channel` 作为独立模块，仍然通过它接收事件
- 但普通外部调用方通常不需要自己显式调用它

语义约束：

- `event_channel` 在接口返回前完成深拷贝，不持有调用方传入指针
- 调用方只负责传入一个已完成解析的只读事件
- `event_channel` 不关心日志目录、文件名、轮转策略和 JSON 格式
- 接口本身应设计为有界、非阻塞、无文件 I/O

建议返回值：

- `0`
  事件已成功进入内核输出队列
- `-EINVAL`
  `event == NULL` 或 `event->version` 不受支持
- `-ENODEV`
  `event_channel` 未初始化完成或已进入关闭流程
- `-ENOSPC`
  队列已满，事件未入队，调用方可据此统计丢包

不建议在该接口中做：

- 睡眠等待用户态消费
- 内核直接写文件
- 内核直接转 JSON
- 把日志路径或文件策略作为参数传进来

### 4.3 推荐调用顺序

当前代码语义下，生产链路中的外部抓取模块推荐顺序如下：

1. 在 hook 现场建立 `task/cred/inode/file` 的稳定引用
2. 在 `workqueue` 或 `kthread` 中调用 `lha_centos9_resolve_event()`
3. `lha_centos9_resolve_event()` 成功返回前，内部自动尝试把结果送入 `event_channel`
4. 如需 JSON 调试输出，再调用 `lha_centos9_format_json()`
5. 调用方释放自己持有的稳定引用

最小调用示意：

```c
struct lha_enriched_event_v1 out;
int rc;

rc = lha_centos9_resolve_event(&capture, &out);
```

如果某个内部流程不想自动送流，则使用：

```c
rc = lha_centos9_resolve_event_no_submit(&capture, &out);
```

## 5. 连续事件输出通道选择

v1 推荐使用：

- `miscdevice`
- 预分配固定容量 ring buffer
- `read() + poll()/epoll()` 的单消费者模型

推荐原因：

- 比 `debugfs` 更适合生产
- 比“内核直接写文件”更安全
- 比自定义 netlink 协议更容易先收敛出稳定实现
- 对 `lha-eventd` 来说，阻塞读 + 批量读模型足够直接

建议设备名：

- 模块名：`lha_centos9_event_channel.ko`
- 设备节点：`/dev/lha_centos9_event_stream`

v1 不建议使用：

- `debugfs` 轮询
- `procfs` 文本输出
- 内核文件落盘
- 多播型 netlink
- mmap 共享大缓冲区

这些方案要么运维边界不清，要么会把可靠性和复杂度一起放大。

## 6. `event_channel` 如何把事件交给用户态

这一节不是在讲 `resolver` 如何解析事件，而是在讲：

- 用户态程序从哪里拿到事件
- 每条事件在字节流里长什么样
- 用户态程序应该怎么等数据、怎么读数据
- 用户态程序怎么判断中间有没有丢事件

换句话说，这一节定义的是：

- `event_channel` 和用户态 `lha-eventd` 之间的通信协议
- 内核把事件交给用户态时，双方要遵守的数据格式和读取规则

可以先把它理解成下面这件事：

- `resolver` 先得到一个 `lha_enriched_event_v1`
- `event_channel` 再把它包装成一条“用户态可读记录”
- `lha-eventd` 从设备节点里把这条记录读出来
- 读出来以后，再决定怎么转成 JSON 和怎么写文件

更直白地说，下面几小节分别在回答这几个问题：

- 用户态从哪里读事件
  通过 `/dev/lha_centos9_event_stream`
- 每条事件长什么样
  不是一坨随意字节，而是 `帧头 + payload`
- 用户态怎么读
  用 `poll()` 等待，再用 `read()` 读取一条或多条完整记录
- 用户态怎么知道有没有丢事件
  看每条记录里的 `seq` 序号是否连续

如果把生产链路拆开看，那么这一节描述的是中间这段：

```text
resolver
    -> event_channel
    -> /dev/lha_centos9_event_stream
    -> lha-eventd
```

下面才是这一层协议的具体 ABI 定义。

### 6.1 共享头文件

建议新增一份内核态与用户态共享的 UAPI 头文件，例如：

- `include/uapi/lha_event_stream.h`

该头文件只描述“内核输出通道到用户态 logger”的稳定 ABI，不直接复用内核内部私有结构。

### 6.2 常量定义

建议定义：

```c
#define LHA_EVENT_STREAM_MAGIC        0x4c484145U
#define LHA_EVENT_STREAM_ABI_V1       1
#define LHA_EVENT_STREAM_DEVICE_NAME  "lha_centos9_event_stream"

enum lha_event_frame_type {
	LHA_EVENT_FRAME_DATA = 1,
};
```

其中：

- `magic`
  用于用户态快速校验读取到的记录是否属于本协议
- `ABI_V1`
  表示“内核输出通道协议版本”
- `FRAME_DATA`
  表示普通事件记录；v1 先只定义这一种

### 6.3 帧头结构

建议每条记录统一包一层固定帧头：

```c
struct lha_event_frame_hdr_v1 {
	__u32 magic;
	__u16 abi_version;
	__u16 frame_type;
	__u16 header_len;
	__u16 payload_version;
	__u32 payload_len;
	__u64 seq;
	__u64 emitted_ns;
	__u32 flags;
	__u32 reserved0;
};
```

字段语义：

- `magic`
  固定为 `LHA_EVENT_STREAM_MAGIC`
- `abi_version`
  当前固定为 `LHA_EVENT_STREAM_ABI_V1`
- `frame_type`
  当前固定为 `LHA_EVENT_FRAME_DATA`
- `header_len`
  当前固定为 `sizeof(struct lha_event_frame_hdr_v1)`
- `payload_version`
  当前固定为 `1`，对应下面的 `lha_event_payload_v1`
- `payload_len`
  当前固定为 `sizeof(struct lha_event_payload_v1)`
- `seq`
  事件流全局序号，用于顺序校验和丢包检测
- `emitted_ns`
  事件成功进入输出通道时的内核时间戳
- `flags`
  预留扩展位，v1 固定为 `0`

### 6.4 负载结构

建议定义一份稳定的用户态可见 payload，语义与当前 `lha_enriched_event_v1` 对齐，但 ABI 上独立命名：

```c
struct lha_event_subject_v1 {
	__u32 pid;
	__u32 tid;
	char scontext[LHA_MAX_CONTEXT_LEN];
	char comm[LHA_MAX_COMM_LEN];
};

struct lha_event_request_v1 {
	__s32 mask_raw;
	char obj_type[LHA_MAX_TYPE_LEN];
	char perm[LHA_MAX_PERM_LEN];
};

struct lha_event_target_v1 {
	char dev[LHA_MAX_DEV_LEN];
	__u64 ino;
	char type[LHA_MAX_TYPE_LEN];
	char path[LHA_MAX_PATH_LEN];
	char tclass[LHA_MAX_TYPE_LEN];
	char tcontext[LHA_MAX_CONTEXT_LEN];
};

struct lha_event_result_v1 {
	__s32 ret;
	char runtime_result[LHA_MAX_RESULT_LEN];
	char policy_result[LHA_MAX_RESULT_LEN];
};

struct lha_event_payload_v1 {
	__u16 version;
	__u16 hook_id;
	__u64 timestamp_ns;
	char hook[LHA_MAX_HOOK_LEN];
	char hook_signature[LHA_MAX_SIG_LEN];
	struct lha_event_subject_v1 subject;
	struct lha_event_request_v1 request;
	struct lha_event_target_v1 target;
	struct lha_event_result_v1 result;
};

struct lha_event_frame_v1 {
	struct lha_event_frame_hdr_v1 hdr;
	struct lha_event_payload_v1 payload;
};
```

设计要求：

- payload 语义与当前 `lha_enriched_event_v1` 一一对应
- 所有字符串字段都必须保证以 `NUL` 结尾
- v1 先使用固定长度结构，不引入 TLV 或变长字段
- 后续若需要扩展字段，优先升级 `payload_version`，不要在 v1 上做不兼容修改

### 6.5 `read()` / `poll()` 协议

建议设备节点支持：

- `open()`
- `read()`
- `poll()` / `epoll()`
- `release()`

v1 约束如下：

- 同一时刻只允许一个 reader 成功 `open()`；第二个 reader 返回 `-EBUSY`
- 阻塞模式下，`read()` 在没有可读事件时休眠等待
- `O_NONBLOCK` 下，无可读事件时返回 `-EAGAIN`
- `read()` 只返回完整的 `struct lha_event_frame_v1`
- `count < sizeof(struct lha_event_frame_v1)` 时返回 `-EINVAL`
- `count` 不是 `sizeof(struct lha_event_frame_v1)` 的整数倍时返回 `-EINVAL`
- 单次 `read()` 可返回 1 条或多条完整记录
- 不支持 `write()`、`mmap()` 和控制命令；调用时返回 `-EOPNOTSUPP`

### 6.6 顺序与丢包语义

`seq` 的推荐语义如下：

- 每次事件真正进入 `event_channel` 队列时先分配一个单调递增序号
- 只有成功入队的事件才能被用户态读到
- 用户态看到的 `seq` 必须严格递增
- 若当前 `seq` 与上一条收到的 `seq` 之间存在 gap，则 gap 大小等于中间丢失事件数

这样做的好处是：

- 用户态无需依赖额外控制面，也能发现通道中是否发生丢包
- 即使 `-ENOSPC` 发生在内核侧，logger 也能从序号断层感知“有事件没到达”

需要明确：

- v1 不提供 per-event ACK
- v1 不提供重放
- v1 不保证“用户态卡住很久后仍然零丢包”

### 6.7 sysfs 统计接口

为了让运维侧观察通道健康度，建议在设备对应的 sysfs 节点下暴露只读属性：

- `abi_version`
- `record_size`
- `queue_capacity`
- `queue_depth`
- `submitted_total`
- `dropped_total`
- `reader_attached`
- `last_drop_ns`

建议路径形态：

- `/sys/class/misc/lha_centos9_event_stream/`

这些统计不属于业务日志内容，但应成为部署诊断的一部分。

## 7. 用户态 `lha-eventd` 接口设计

### 7.1 进程职责

`lha-eventd` 只负责：

- 独占打开 `/dev/lha_centos9_event_stream`
- 批量读取 `struct lha_event_frame_v1`
- 校验 `magic/version/size`
- 把 `payload` 序列化为 JSON
- 按天把 JSON 追加到目标日志文件
- 处理 flush、fsync、切换文件和错误重试

`lha-eventd` 不负责：

- 回写内核 ACK
- 参与 hook 抓取
- 参与 resolver 解析
- 修改内核输出策略

### 7.2 配置接口

v1 建议同时支持：

- 默认配置文件 `/etc/lha-eventd.conf`
- 命令行参数覆盖配置文件

建议最小配置项：

```ini
device_path=/dev/lha_centos9_event_stream
output_dir=/var/log/lha
flush_interval_ms=1000
fsync_interval_ms=5000
max_batch_records=128
dir_mode=0750
file_mode=0640
```

字段语义：

- `device_path`
  连续事件输出通道设备节点
- `output_dir`
  最终日志根目录
- `flush_interval_ms`
  用户态缓冲刷到内核页缓存的周期
- `fsync_interval_ms`
  调用 `fsync()` 的周期
- `max_batch_records`
  每轮处理的最大记录数
- `dir_mode` / `file_mode`
  目录与日志文件权限

v1 不建议把“按什么目录分桶、按什么文件名模板分桶”做成特别自由的模板系统；先固定成“目录可配，文件名按天”，能显著降低实现复杂度。

### 7.3 主循环约束

建议 `lha-eventd` 主循环如下：

1. 打开设备节点
2. `poll()` 等待可读
3. 一次 `read()` 批量取回若干 `struct lha_event_frame_v1`
4. 校验每条记录的 `magic`、`abi_version`、`payload_version`、`payload_len`
5. 把 `payload` 转成单行 JSON
6. 按 `payload.timestamp_ns` 计算应写入的本地日期文件
7. 追加写入并补 `\n`
8. 按配置周期执行 `fflush()` / `fsync()`

重要策略：

- 日志文件分桶应基于事件自身 `timestamp_ns`，而不是“logger 当前写入时刻”
- 如果积压事件跨天到达，仍应按事件发生日期落到对应文件
- 文件名使用主机本地时区对应的 `YYYY-MM-DD.log`

### 7.4 JSON 输出约束

v1 建议最终文件内容采用 NDJSON，并保持与当前 `lha_centos9_format_json()` 一致的业务字段集合：

- `hook`
- `hook_signature`
- `timestamp_ns`
- `subject`
- `request`
- `target`
- `result`

即：

- 生产日志的 JSON 语义应尽量与当前 `last_json` 保持兼容
- 通道帧头中的 `seq`、`emitted_ns`、`flags` 默认不写入业务日志
- 如需写入通道元数据，应作为未来可选增强，而不是 v1 默认行为

这样做的好处是：

- 当前调试链路观察到的 JSON 结构可以直接延续到生产
- 下游分析脚本后续更容易从 `last_json` 迁移到日常日志文件

### 7.5 文件命名与切分

v1 只定义一种切分策略：

- 文件路径：`<output_dir>/YYYY-MM-DD.log`
- 打开模式：`O_CREAT | O_APPEND | O_WRONLY`
- 同一天内持续追加
- 下一天第一次写入时懒切换到新文件

v1 暂不做：

- 小时级切分
- 大小触发切分
- 自动压缩
- 自动清理保留天数

这些策略适合在 logger 稳定后再加，而不是一开始就压进接口设计。

### 7.6 故障处理约束

`lha-eventd` 建议按以下原则处理故障：

- 设备节点暂时不可用
  进入重试循环，指数退避重连
- 读到非法帧头
  视为 ABI 不匹配或严重错误，记录错误后退出
- 输出目录创建失败
  停止消费并重试，不要“边读边丢”
- 文件写入或 `fsync()` 失败
  停止继续从设备读取，优先恢复落盘链路

核心原则是：

- 不要为了“保持 logger 自己看起来还活着”而静默吞掉事件
- 一旦后端落盘不可用，应让内核队列承担短期缓冲
- 如果缓冲最终耗尽，丢包应体现在 `seq` gap 和 `dropped_total` 上

## 8. 与现有调试链路的关系

当前已有链路：

```text
injector
    -> resolve_event
    -> format_json
    -> debugfs last_json
```

该链路继续保留，但定位不变：

- 用于自测
- 用于调试 JSON 结构
- 用于验证 resolver API

生产链路不应再依赖：

- `debugfs`
- `last_json`
- 内核态 JSON 持续输出

## 9. v1 不做的事情

为了控制边界，下面这些能力明确不进入本次 v1：

- 多用户态消费者
- 内核态到用户态的可靠 ACK / 重放
- 通道内持久化队列
- 远程日志传输
- 内核态动态日志目录
- 通道内直接输出 JSON 文本
- 混合多种输出后端

如果后续要做更复杂能力，建议在 `event_channel` 或 `lha-eventd` 层面演进，不要改动 `resolver` 的职责定义。

## 10. 推荐落地顺序

建议按下面顺序推进实现：

1. 新增共享 UAPI 头文件，先冻结 `frame header + payload` 结构
2. 实现 `lha_centos9_event_channel.ko` 和 `lha_centos9_submit_event()`
3. 在 `resolver` 中补上自动送流注册/调用逻辑，并保留 `lha_centos9_resolve_event_no_submit()`
4. 暴露 `/dev/lha_centos9_event_stream` 与基础 sysfs 统计
5. 实现 `lha-eventd` 的阻塞读、NDJSON 序列化与按天落盘
6. 最后再补充 systemd service、日志权限、重试和观测项

这样推进的好处是：

- 先把最关键的 ABI 固定住
- 再分别实现内核侧和用户态
- 后续就算扩容队列、优化性能，也不会轻易影响上层接口

## 11. 结论

生产级方案的关键不是让 `resolver` 学会“持续写日志”，而是把职责分成三段：

- `resolver` 产出稳定结构化事件
- `event_channel` 提供连续、可观测的本机事件流
- `lha-eventd` 负责序列化、目录、命名、轮转和落盘

对当前仓库而言，v1 最合适的接口收敛方式是：

- 外部调用方主要走 `lha_centos9_resolve_event()`
- `lha_centos9_resolve_event()` 成功返回前自动尝试送流
- 内部少数场景使用 `lha_centos9_resolve_event_no_submit()`
- 底层继续保留 `lha_centos9_submit_event()`
- 用 `miscdevice + ring buffer + read/poll` 做连续输出通道
- 用 `lha-eventd` 把 `lha_event_payload_v1` 写成与当前 JSON 语义兼容的日切 NDJSON 日志

这条路径既延续了 7.4 的分层方向，也尽量不打破当前项目已经形成的 `resolver` 边界。
