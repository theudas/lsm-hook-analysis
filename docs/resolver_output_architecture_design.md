# Resolver 输出架构设计说明

## 1. 文档目标

本文档用于澄清当前 `lha_centos9_resolver` 的接口设计思路，并给出面向未来多 hook、大事件量场景的可扩展输出架构。

重点回答 3 个问题：

1. 为什么当前核心接口是：

   ```c
   int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
   			      struct lha_enriched_event_v1 *out);
   ```

2. 为什么不建议让 resolver 在解析后直接写日志文件或大量打印内核日志。
3. 如果未来 hook 数量增多、事件量显著上升，生产级输出链路应该如何设计。

本文档中的“当前实现”表示仓库里已经存在的行为；“推荐方案”表示后续架构演进建议，不代表代码已经实现。

## 2. 当前架构概览

当前仓库中与事件处理相关的内核模块有 3 个：

- `lha_centos9_resolver.ko`
  核心解析模块
- `lha_centos9_avc_capture.ko`
  真实 AVC deny 抓取模块
- `lha_centos9_injector.ko`
  debugfs 自测模块

逻辑关系如下：

```text
外部 hook 抓取模块
    -> 组装 lha_capture_event_v1
    -> lha_centos9_resolve_event()
    -> 得到 lha_enriched_event_v1
    -> 调用方自行决定后续如何消费

selinux_audited tracepoint
    -> lha_centos9_avc_capture.ko
    -> lha_centos9_record_avc_event()
    -> resolver 内部 AVC 缓存

debugfs inject
    -> lha_centos9_injector.ko
    -> lha_centos9_resolve_event()
    -> lha_centos9_format_json()
    -> /sys/kernel/debug/lha_centos9/last_json
```

这里最重要的一点是：

- `resolver` 负责“解析”
- `injector` 负责“开发/自测链路里的简单输出”
- 当前并没有生产级、连续消费型的事件输出通道

## 3. 当前核心接口为什么是 `in -> out`

当前接口：

```c
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out);
```

这个接口设计不是偶然的，它反映了当前架构的一个核心原则：

- resolver 只做“从原始 hook 输入到结构化结果”的纯解析工作
- resolver 不负责“决定输出到哪里、以什么格式输出、何时落盘”

### 3.1 输入结构的职责

`struct lha_capture_event_v1` 表达的是：

- 这是一条什么 hook 事件
- 原始参数是什么
- 主体是谁
- 运行时返回值是什么

它是“原始输入事件”的承载体。

### 3.2 输出结构的职责

`struct lha_enriched_event_v1` 表达的是：

- 解析后的主体信息
- 解析后的目标对象信息
- 权限语义
- 运行时结果
- 策略关联结果

它是“结构化解析结果”的承载体。

### 3.3 为什么由调用方提供 `out`

采用调用方提供 `out` 指针，而不是 resolver 自己分配输出对象，有以下好处：

- 避免 resolver 额外管理对象生命周期
- 避免隐藏内存分配行为
- 让调用方可以自行决定 `out` 的存储位置
- 便于把 resolver 嵌入不同的上层处理链路

调用方可以：

- 只读取 `out` 的字段
- 再调用 `lha_centos9_format_json()`
- 把 `out` 复制到自己的队列
- 把 `out` 编码后发送到用户态

也就是说，当前接口天然支持“解析和输出分层”。

## 4. 当前设计为什么不应直接写日志

从开发直觉上看，“resolver 既然已经拿到了完整结果，为什么不直接把 JSON 写到日志里”是一个自然问题。但在当前项目里，不建议这么做。

## 4.1 不建议直接写用户态目录文件

例如直接让内核模块写：

```text
/path/to/project/log/YYYY-MM-DD.log
```

不建议的原因包括：

- 项目根目录是开发环境概念，不是稳定的生产环境路径
- 内核里做文件 I/O 风险高，失败恢复复杂
- 日志目录动态切换会让内核逻辑变得笨重
- 文件系统、权限、SELinux、磁盘错误都需要额外处理
- 大量事件下，文件 I/O 会直接拖慢解析链路

简言之：

- 解析逻辑属于内核态
- 目录管理、落盘策略、文件轮转属于用户态

这两类职责不应该强耦合。

## 4.2 不建议把内核日志当生产主日志链路

虽然当前代码里可以用 `pr_info()` / `pr_warn()` 打日志，但这类内核日志更适合：

- 调试
- 运行状态提示
- 错误告警

不适合作为大量事件的正式输出通道，原因包括：

- `dmesg` / journald 不是专用事件队列
- 高频事件会污染系统内核日志
- 单条日志长度和格式控制较弱
- 不适合承载大量结构化 JSON
- 无法很好支持动态目录、文件轮转、归档策略

## 5. 当前 `injector + last_json` 链路为什么不适合生产

当前自测链路是：

```text
injector
    -> resolve
    -> format_json
    -> last_json
```

这条链路的定位是：

- 自测
- 演示 JSON 输出结构
- 手工验证 resolver 行为

它不适合作为生产输出，主要问题有：

- `last_json` 只保留最近一次结果
- 连续事件会覆盖前一条结果
- 外部轮询单文件会丢中间事件
- 不适合很多 hook 并发上报
- 不具备顺序号、丢包检测、背压控制等能力

因此，当前链路可以保留为开发/自测入口，但不应扩展为生产主输出方案。

## 6. 设计原则

面向未来多 hook 场景，推荐坚持以下原则。

### 6.1 解析与输出解耦

- resolver 只负责把 `lha_capture_event_v1` 转成 `lha_enriched_event_v1`
- 输出通道独立设计
- JSON 序列化不是 resolver 的唯一消费方式

### 6.2 内核只输出结构化事件，不做复杂落盘策略

内核里更适合做：

- 结构体填充
- 轻量归一化
- 环形队列或消息投递

内核里不适合做：

- 多目录管理
- 文件轮转
- 复杂重试
- 长时间阻塞式文件 I/O

### 6.3 用户态决定最终日志目录和文件命名

这类能力应由用户态守护进程承担：

- 输出目录可动态调整
- `YYYY-MM-DD.log` 文件切分
- 文件轮转
- fsync 策略
- 日志清理和归档

### 6.4 输出链路必须支持连续消费

生产输出通道至少应满足：

- 多事件不覆盖
- 有明确的顺序语义
- 有丢事件统计或可检测能力
- 用户态能持续消费

## 7. 生产级输出方案候选

## 7.1 方案 A：继续使用 `debugfs + 单文件轮询`

做法：

- resolver 或 injector 持续更新某个 debugfs 文件
- 用户态脚本轮询并写文件

优点：

- 最容易做
- 适合演示和临时调试

缺点：

- 只能保留最后一条或极少量结果
- 容易丢事件
- 不适合大吞吐
- 不适合很多 hook

结论：

- 仅适合开发/自测

## 7.2 方案 B：直接写内核日志

做法：

- resolver 解析后直接 `pr_info()`

优点：

- 极易实现
- 适合临时调试

缺点：

- 不适合结构化批量事件
- 污染系统内核日志
- 无法承载动态目录策略

结论：

- 仅适合调试

## 7.3 方案 C：内核直接写文件

做法：

- resolver 内部直接 `filp_open()` + `kernel_write()`

优点：

- 看上去最直接

缺点：

- 架构边界差
- 风险高
- 不利于扩展
- 不利于维护

结论：

- 不推荐

## 7.4 方案 D：连续事件输出通道 + 用户态 logger

做法：

- resolver 继续只产出 `lha_enriched_event_v1`
- 新增独立事件输出通道
- 用户态守护进程负责读取、序列化、落盘

优点：

- 架构清晰
- 易于支持很多 hook
- 目录可动态调整
- 易于做轮转、限速、归档

缺点：

- 需要新增一层组件

结论：

- 推荐作为生产级方案

## 8. 推荐的生产级演进方向

推荐架构如下：

```text
外部 hook 抓取模块
    -> lha_centos9_resolve_event(in, &out)
    -> 事件输出通道
    -> 用户态 logger
    -> /configured/log/dir/YYYY-MM-DD.log
```

这里最关键的变化是：

- `lha_enriched_event_v1` 成为内核态与输出链路之间的稳定中间结果
- JSON 序列化和文件落盘后移到用户态

## 8.1 推荐的模块分层

### 内核态

- `resolver`
  负责解析
- `avc_capture`
  负责 deny 线索补充
- `event_sink`
  负责连续事件输出通道

### 用户态

- `lha-eventd`
  负责读取事件、写日志、切分文件、支持动态目录

## 8.2 内核态推荐接口边界

当前保留：

```c
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out);
```

推荐新增一层输出接口，例如：

```c
int lha_centos9_submit_event(const struct lha_enriched_event_v1 *event);
```

语义：

- resolver 不关心日志目录
- resolver 不关心最终文件名
- resolver 只把结构化结果交给输出通道

## 8.3 用户态 logger 的职责

用户态 logger 应负责：

- 读取连续事件流
- 可选转 JSON
- 写入动态可配置目录
- 文件按 `YYYY-MM-DD.log` 命名
- 处理轮转、flush、fsync、错误重试

这类逻辑放在用户态更合理，也更容易运维。

## 9. 设计收益

坚持“resolver 产出结构体，输出链路独立”的设计，能带来这些收益：

- 避免 resolver 被日志策略绑死
- 减少内核态文件 I/O 风险
- 更容易扩展新的 hook
- 更容易支持不同输出后端
- 更容易做性能优化和容量治理

更重要的是：

- 未来新增 hook 时，resolver 的职责不变
- 输出链路只消费统一的 `lha_enriched_event_v1`

这使得“扩展 hook 数量”和“扩展输出能力”可以分别演进，而不会互相牵扯。

## 10. 当前阶段的建议

当前项目阶段建议分两条线：

### 开发/自测链路

继续保留：

- `injector`
- `debugfs`
- `last_json`
- 用户态简单归档脚本

用于：

- 手工验证
- 快速调试
- 观察 JSON 结构

### 生产链路

下一步逐步引入：

- 连续事件输出通道
- 用户态 logger
- 动态目录配置

不要基于 `last_json` 或内核直接写文件来扩展生产方案。

## 11. 结论

当前 `lha_centos9_resolve_event(in, out)` 的设计是合理的，而且应当继续保留。它体现的是：

- resolver 只做解析
- 结构化结果通过 `out` 向外返回
- 输出、日志、目录管理属于 resolver 之外的职责

这不是“功能不完整”，而是一个有意保留扩展空间的分层设计。

如果未来要支持很多 hook 和生产级日志链路，正确方向不是让 resolver 直接写日志，而是：

1. 保持 resolver 继续产出 `lha_enriched_event_v1`
2. 单独设计连续事件输出通道
3. 由用户态 logger 决定目录、命名、轮转和落盘策略
