# AVC 关联设计

## 1. 文档目标

本文档给出一套面向当前仓库的 `policy_result` 获取设计，重点回答下面几个问题：

- 为什么单靠现有 hook 事件无法稳定得到 `policy_result`
- 如果引入 AVC 关联，系统边界应该怎么划分
- v1 版本应该先做到什么程度
- 如果采用“未观测到 AVC deny 即推断 allow”的策略，语义边界应该如何表达

本文档是设计稿，不代表代码已经实现。

## 2. 背景

当前仓库已经能较稳定地产生下面这些信息：

- `subject`
- `request`
- `target`
- `ret`
- `runtime_result`

但是 `policy_result` 还缺少稳定来源。

根因不是 resolver 不够复杂，而是输入信息本身不充分。

当前 hook 侧能拿到的大致是：

- hook 类型
- `task/cred`
- `inode/file`
- `mask`
- `ret`

这些字段足够恢复“谁访问了什么、请求了什么、运行时返回什么”，但不一定足够恢复“SELinux 策略层本来是 allow 还是 deny”。

最典型的反例是 permissive 模式：

- policy deny
- runtime allow
- `ret == 0`

这时如果只看 `ret`，就会把它误判成 policy allow。

因此，`policy_result` 必须来自额外的策略判定来源，而不是从现有 hook 参数硬推。

如果采用 AVC 作为主要证据源，那么 v1 可以把“未在 AVC 日志中观测到 deny”作为 allow 的推断依据，但必须明确这个值是推断而不是强证明。

## 3. 设计结论

### 3.1 总结

如果做 AVC 关联，本仓库建议采用：

- hook 事件继续负责恢复资源访问语义
- AVC 路径负责提供策略层 deny 线索
- 关联层负责把两类事件合并
- resolver / JSON 输出层负责统一输出 `policy_result`

### 3.2 推荐的 v1 目标

推荐先实现：

- `policy_result = deny`
- `policy_result = inferred_allow`
- `policy_result = unknown`

不建议在 AVC-only 的第一版里把未命中的情况直接命名成强语义的 `allow`。

原因是 AVC 事件天然更适合表达“拒绝发生了”，而“未观测到 deny”本质上只是负证据推断。

换句话说：

- 能可靠匹配到 AVC deny -> `policy_result = deny`
- 在观测窗口内没有匹配到 AVC deny，并且匹配前提成立 -> `policy_result = inferred_allow`
- 如果事件本身不具备完成匹配所需的关键字段 -> `policy_result = unknown`

这版已经能解决当前最关键的问题：

- 在 permissive 模式下识别“policy deny + runtime allow”
- 在 enforcing 模式下把“policy deny + runtime deny”从 `ret` 的影子推断变成真正的策略结论
- 在没有 deny 证据时，给出一个可消费的推断型 allow 结果

### 3.3 长期目标

如果后续需要完整的：

- `policy_result = allow`
- `policy_result = deny`
- `policy_result = inferred_allow`
- `policy_result = unknown`

则建议在 AVC 关联之外，再补一条更靠近 SELinux decision 的采集路径。

## 4. 设计范围

### 4.1 本设计覆盖

- hook 事件与 AVC 事件的关联
- `policy_result` 的状态定义
- 待关联缓存结构
- 匹配规则
- 超时与淘汰策略
- 后续代码拆分建议

### 4.2 本设计暂不覆盖

- 目标 CentOS Stream 9 内核树里具体要挂的最终函数名
- 用户态 audit 日志解析的完整实现
- 最终生产输出通道的选型
- 完整 `policy allow` 的稳定判定方案

上面这些点在 coding 前还需要结合目标内核源码再确认。

## 5. 方案选型

## 5.1 方案 A：只看 hook 事件

做法：

- 继续只采集 `task/cred/inode/file/mask/ret`
- 不增加任何 AVC 或策略路径

优点：

- 实现最简单
- 没有额外关联逻辑

缺点：

- permissive 模式下一定会误判
- `policy_result` 只能伪造，不能真实恢复

结论：

- 不可接受

## 5.2 方案 B：AVC 关联

做法：

- 保留现有 hook 采集
- 额外采集 AVC 相关事件
- 按字段和时间窗口做关联

优点：

- 可以落地
- 能较可靠识别 deny
- 能覆盖 permissive 下的 policy deny
- 能在没有 deny 证据时给出 `inferred_allow`

缺点：

- `inferred_allow` 只是一种推断，不是强证明
- 需要维护待匹配缓存
- 匹配规则设计不好会出现误配或漏配

结论：

- 推荐作为 v1

## 5.3 方案 C：Decision 路径采集

做法：

- 直接采集更靠近 SELinux 决策内部的位置
- 让采集侧直接拿到策略判定结果

优点：

- 理论上最完整
- 更接近真实策略结论

缺点：

- 对内核版本更敏感
- 研发和验证成本更高
- 对当前项目来说不适合作为第一步

结论：

- 推荐作为 v2 / v3 能力

## 5.4 最终建议

推荐采用分阶段路线：

1. v1：先做 AVC 关联，输出 `deny/inferred_allow/unknown`
2. v2：再评估 decision 路径，把强语义 `allow` 也补齐

## 6. 推荐架构

建议把系统拆成 4 层：

1. hook 采集层
2. AVC 采集层
3. 关联层
4. resolver / 输出层

逻辑上如下：

```text
hook capture
    -> hook worker
    -> enriched hook event
    -> correlator
         ^ 
         |
avc capture
    -> avc worker
    -> normalized avc event
```

关联成功后，再产生最终输出：

```text
correlated event
    -> policy_result = deny
    -> json output
```

未命中 deny 时则：

```text
policy_result = inferred_allow 或 unknown
```

## 7. 为什么推荐“先 resolve，再做 AVC 关联”

当前 hook 原始输入里并没有足够稳定的匹配键。

真正适合做关联的字段，反而是在 resolver 之后才稳定出现：

- `subject.scontext`
- `target.tcontext`
- `target.tclass`
- `request.perm`
- `hook`

因此，本仓库内部如果要自己做 AVC 关联，推荐流程是：

1. 先用现有 resolver 生成 enriched hook event
2. 从 enriched hook event 提取关联键
3. 与 AVC 事件做匹配
4. 再回填 `policy_result`

这里有一个重要结论：

- `event.policy_state` 这个字段依然有价值，但更适合外部关联器把结果提前塞回 resolver
- 如果关联逻辑直接做在本仓库内部，实际实现更自然的是“resolve 后匹配，再回填结果”

也就是说，`policy_state` 不是没用，而是它更像：

- 外部策略结果注入口

而本仓库内置 AVC 关联则更像：

- resolver 后置增强器

## 8. 事件模型建议

## 8.1 Hook 侧待关联结构

建议在 resolver 之后生成一个待关联对象：

```c
struct lha_pending_hook_event {
    u64 id;
    u64 ts_ns;
    u64 expire_ns;

    struct lha_enriched_event_v1 event;

    bool matched;
};
```

说明：

- `id` 用于内部跟踪
- `ts_ns` 是 hook 事件时间
- `expire_ns` 用于超时淘汰
- `event` 是当前仓库已经有的 enriched 结果

## 8.2 AVC 侧标准化结构

建议引入一个仓库内使用的标准化 AVC 事件：

```c
struct lha_avc_event_v1 {
    u64 id;
    u64 ts_ns;
    u64 expire_ns;

    char scontext[256];
    char tcontext[256];
    char tclass[32];
    char perm[64];

    u32 pid;
    u32 tid;
    char comm[16];

    bool permissive;
    bool denied;
};
```

说明：

- `scontext/tcontext/tclass/perm` 是核心匹配键
- `pid/tid/comm` 是辅助匹配键
- `permissive` 用于区分“policy deny + runtime allow”
- `denied` 表示该 AVC 事件表达的是 deny 结论

注意：

- 上面是仓库内部归一化结构
- 不要求底层 AVC 采集源天然就长这样
- 无论底层来自内核探针还是 audit 日志，最后都应转换成这一个结构

## 8.3 关联状态建议

如果要支持 `inferred_allow`，至少需要把结果语义区分成“正证据 deny”和“负证据推断 allow”。

建议至少维护下面这类状态：

```c
enum lha_policy_result_kind {
    LHA_POLICY_RESULT_UNKNOWN = 0,
    LHA_POLICY_RESULT_DENY,
    LHA_POLICY_RESULT_INFERRED_ALLOW,
    LHA_POLICY_RESULT_ALLOW,
};
```

其中：

- `DENY` 表示有正向 deny 证据
- `INFERRED_ALLOW` 表示在观测窗口内没有 deny 证据，且事件具备完成匹配所需的关键字段
- `UNKNOWN` 表示无法安全推断
- `ALLOW` 预留给未来 decision 路径的强语义 allow

这里的关键点是：

- `DENY` 依赖正向 AVC 证据
- `INFERRED_ALLOW` 依赖“窗口内未观测到 deny”的推断
- `UNKNOWN` 只在事件关键字段缺失、无法完成匹配时使用

## 9. 匹配键设计

## 9.1 主匹配键

推荐主键使用：

- `subject.scontext`
- `target.tcontext`
- `target.tclass`
- `request.perm`

原因：

- 这些字段直接对应 SELinux 策略判定的关键维度
- 相比路径，SELinux context 更稳定
- 相比 inode 指针，字符串键更适合跨事件源关联

## 9.2 辅助匹配键

辅助键建议使用：

- `subject.pid`
- `subject.tid`
- `subject.comm`
- 时间窗口

原因：

- 相同 `scontext/tcontext/tclass/perm` 在高并发场景下可能同时出现多次
- 需要用进程维度和时间窗口进一步缩小候选集合

## 9.3 不建议作为主键的字段

不建议把下面这些字段作为第一优先级匹配键：

- 路径
- `inode *`
- `file *`
- `ret`

原因：

- 路径可能恢复不完整
- `inode/file` 无法跨事件源稳定复用
- `ret` 反映的是运行时，不是策略层

## 9.4 权限字段归一化

`request.perm` 在关联前应做归一化。

例如：

- `open|read`
- `append`
- `search`

需要确保 AVC 事件侧也输出相同口径的字符串或位图，不然会出现明明是同一件事却无法匹配。

因此建议：

- 内部匹配不要只依赖文本字符串
- 最好同时保留规范化字符串和内部位图表示

## 10. 匹配规则

推荐使用“先精确、再缩小”的规则，而不是模糊打分。

### 10.1 基础规则

一条 hook 事件与一条 AVC 事件匹配，需要同时满足：

- `scontext` 相同
- `tcontext` 相同
- `tclass` 相同
- `perm` 相同或 AVC 权限集合包含 hook 请求权限
- 时间差在窗口内

### 10.2 强化规则

如果基础规则命中多条候选，再继续比较：

- `tid`
- `pid`
- `comm`

### 10.3 最终选择规则

如果仍有多个候选，选择：

- 时间差最小的一条

如果最佳候选仍然不够唯一，则：

- 放弃匹配
- 保持 `policy_result = unknown`

结论是：

- 宁可漏配，也不要误配

## 11. 时间窗口设计

建议把匹配窗口做成可配置项。

v1 可以先给一个保守默认值，例如：

- `50ms`

如果 AVC 采集链路更异步，也可以放宽到：

- `100ms`
- `200ms`

但窗口越大，误配概率越高。

因此推荐默认策略：

- 内核内关联：窗口更小
- 跨内核到用户态 audit 日志关联：窗口更大

一条 hook 事件只有在窗口结束后仍未看到匹配的 AVC deny，才允许进入 `inferred_allow` 判定。

## 12. 关联结果语义

## 12.1 v1 输出规则

如果匹配到 AVC deny：

- `policy_result = deny`

如果在观测窗口内未匹配到 AVC deny，且事件具备匹配所需的关键字段：

- `policy_result = inferred_allow`

如果事件本身缺少关键匹配字段：

- `policy_result = unknown`

如果运行时是 `allow`，但匹配到一条 `permissive = true` 的 AVC deny：

- `runtime_result = allow`
- `policy_result = deny`

这正是该设计最有价值的一类场景。

## 12.2 为什么 v1 不直接输出 allow

因为“没有看到 AVC deny”不等于“拿到了强证明的 policy allow”。

可能出现：

- 事件丢失
- audit 没覆盖
- 匹配失败
- AVC 链路延迟超过窗口

因此 v1 里：

- 未命中 deny 时只输出 `inferred_allow`
- 只有在字段完整、具备匹配前提时才允许这样推断
- 任何不满足匹配前提的情况都回退为 `unknown`

## 13. 数据流建议

## 13.1 Hook 事件流

建议流程：

1. hook 现场抓原始事件
2. 放入 workqueue
3. 调用现有 resolver 生成 `lha_enriched_event_v1`
4. 放入 `pending_hook` 表等待关联
5. 如果超时仍未匹配：
   - 匹配前提成立 -> 输出 `inferred_allow`
   - 匹配前提不成立 -> 输出 `unknown`

## 13.2 AVC 事件流

建议流程：

1. AVC 采集侧抓到 deny 事件
2. 归一化成 `lha_avc_event_v1`
3. 放入 `pending_avc` 表
4. 尝试与 `pending_hook` 表中的候选事件匹配
5. 匹配成功后回填 hook 事件的 `policy_result`

## 13.3 输出时机

有两种可接受的输出方式：

### 方式 A：延迟输出

- hook 事件先进入 pending
- 等一个短窗口
- 关联完成后再统一输出

优点：

- 输出天然完整

缺点：

- 所有事件都会引入额外延迟

### 方式 B：两阶段输出

- 先输出基础事件
- 关联成功后再输出一条补充/修正事件

优点：

- 主链路延迟小

缺点：

- 消费端更复杂
- 同一事件需要去重或合并

对当前仓库来说，更推荐：

- 方式 A

因为当前项目本身更偏解析和结构化输出，先保证语义完整更重要。

## 14. 缓存与并发设计

建议至少维护两个待匹配容器：

- `pending_hook`
- `pending_avc`

每个容器里的元素都需要：

- 插入时间
- 过期时间
- 已匹配标记

实现上建议：

- 哈希表 + LRU/超时淘汰

哈希主键建议用：

- `scontext`
- `tcontext`
- `tclass`

把候选集合先缩小，再在桶内按 `perm + pid/tid + ts` 精配。

并发控制建议：

- v1 先用自旋锁或 mutex 保证正确性
- 不要一开始就过度设计成 lock-free

## 15. AVC 采集来源选择

## 15.1 内核内 AVC 探针

做法：

- 在内核里直接采集 AVC 相关事件

优点：

- 结构化数据更直接
- 时间基准更统一
- 关联延迟更小

缺点：

- 更依赖目标内核版本
- coding 前必须核对 CentOS Stream 9 具体挂点

## 15.2 用户态 audit 日志解析

做法：

- 从 audit 日志中读取 AVC 事件
- 在用户态做归一化和关联

优点：

- 不需要深入修改内核模块
- 可以先做验证性原型

缺点：

- 需要解析文本日志
- 时序更松散
- 掉日志、延迟、字段不齐全都会影响匹配

## 15.3 推荐

如果目标是：

- 先验证匹配可行性

可以先做：

- 用户态 audit 原型

如果目标是：

- 与当前仓库的内核态 resolver 深度整合

更推荐：

- 内核内 AVC 采集

## 16. 与当前代码的衔接建议

当前仓库已经有：

- `lha_centos9_resolve_event()`
- `lha_centos9_format_json()`
- `struct lha_capture_event_v1.policy_state`

但如果要把 AVC 关联直接做进本仓库，建议新增一层“后置关联接口”，而不是强行要求 AVC 一定发生在 resolver 之前。

推荐增加的内部能力是：

1. 生成 enriched hook event
2. 与 AVC 标准化事件关联
3. 在 `struct lha_enriched_event_v1.result.policy_result` 上回填结果
4. 在未命中 deny 时，根据匹配前提是否成立决定填 `inferred_allow` 还是 `unknown`

`policy_state` 字段仍然保留，作为：

- 外部模块已经有策略结论时的直接注入口

这样可以兼容两种使用方式：

- 外部先关联，再调用 resolver
- 本仓库内部关联，再统一输出

## 17. 分阶段实施建议

## 17.1 Phase 1

目标：

- 先把数据结构和关联框架搭起来

建议做法：

- 新增 AVC 标准化结构
- 新增 pending 缓存
- 新增匹配函数
- 支持 `deny/inferred_allow/unknown`
- 明确关键字段缺失时的 `unknown` 回退规则

产出：

- 设计上闭环
- 可以开始做假事件单元测试

## 17.2 Phase 2

目标：

- 接入真实 AVC 采集源

建议做法：

- 先确定是内核探针还是用户态 audit 原型
- 打通 AVC 事件入队
- 完成真实关联

产出：

- permissive deny 可见
- enforcing deny 可显式表达为 policy deny
- 正常未命中 deny 的事件可以输出 `inferred_allow`

## 17.3 Phase 3

目标：

- 评估 `policy allow` 的获取路径

建议做法：

- 研究更靠近 SELinux decision 的挂点
- 明确能否稳定得到 allow 决策

产出：

- `allow/deny/inferred_allow/unknown` 完整语义

## 18. 测试建议

测试至少应覆盖下面几类场景：

1. enforcing deny
2. permissive deny
3. 正常 allow 且无 AVC
4. 关键字段缺失时的 unknown 回退
5. 同一时刻多个相似请求并发
6. AVC 晚到
7. AVC 先到
8. 超时淘汰
9. 一条 AVC 对多条 hook 候选的歧义选择

特别要验证：

- permissive deny 最终应表现为：
  - `runtime_result = allow`
  - `policy_result = deny`

## 19. 风险与边界

主要风险：

- AVC 字段不全，导致匹配不稳
- 时间窗口设置不合适，导致误配或漏配
- 高并发场景下同类事件过多，歧义上升
- 如果 AVC 来源过于依赖私有内核实现，版本迁移成本会上升
- `inferred_allow` 会被误当成强 allow 使用

因此 v1 应坚持：

- 先求正确
- 再求覆盖率
- `deny` 必须来自正证据
- `inferred_allow` 必须明确是推断值
- 关键字段缺失时宁可回退 `unknown`

## 20. 审阅时建议重点确认的问题

请重点确认下面几项是否符合预期：

1. v1 是否接受 `policy_result` 输出 `deny/inferred_allow/unknown`
2. 关联位置是放在 resolver 之后，还是必须要求外部模块先关联
3. AVC 真实来源优先做内核探针，还是先做用户态 audit 原型
4. 默认输出模式是延迟输出，还是两阶段输出
5. 时间窗口默认值希望偏保守还是偏宽松
6. `inferred_allow` 是否直接写入 `policy_result`，还是需要额外增加来源/置信度字段

## 21. 当前建议

基于当前仓库状态，我的建议是：

1. 先接受 v1 做 `deny/inferred_allow/unknown`
2. 关联逻辑放在 resolver 之后
3. 实现里明确把 `inferred_allow` 当作推断值处理
4. 先把仓库内部的数据结构、缓存、匹配接口写好
5. 真实 AVC 来源在 coding 前再结合目标内核树确认

这样推进的好处是：

- 不会一开始就把接口绑死在某个不稳定的内核私有挂点上
- 可以先把主链路架起来
- 后续无论 AVC 来自内核还是 audit 日志，都有统一落点
- 当前业务又能尽早消费一个可解释的“未观测 deny”结果
