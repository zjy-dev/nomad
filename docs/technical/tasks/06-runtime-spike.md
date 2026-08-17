# Native Runtime Spike 任务

本组任务验证 D-006/H9，不属于 Validation Companion 发布关键路径。代码与依赖必须隔离在 `runtime-spike/`，不得为了展示 Rust 原型修改 Companion contract 语义。

## RT-001：预登记 Runtime benchmark 与决策规则

- Size：S
- Depends on：G0、HC-001
- 关联：D-006；Validation E5、6.3
- 目标：在实现前冻结 3 至 5 个产品 workload、权重、环境和非退化预算。
- 交付：冷启动、100k 事件恢复、durable append、长 Session RSS 等 workload；固定 OpenCode release；fixture hash；统计方法；go/no-go 表。
- 验收：Provider 使用本地 replay mock；SQLite PRAGMA/durability 相同；记录 p50/p95/p99、CPU、peak RSS、allocation 和 I/O；至少一个关键 workload 的 2x/40% 门槛和其他 workload 预算在代码前冻结。
- 排除：选择性删掉不利 workload 和拿源码开发模式对比 release。

## RT-002：实现 Rust SQLite schema 与只读 Session API

- Size：M
- Depends on：CON-001、RT-001
- 关联：路线图 4.2
- 目标：建立最小 Session/message/history 读取内核。
- 交付：schema、migration、分页 API、版本检查和 fixture loader。
- 验收：与预登记 fixture 兼容 100%；未知 schema 明确拒绝；只读 API 通过 conformance；不写 OpenCode 生产数据库，只操作 spike 数据副本。
- 排除：Provider、工具、TUI 和数据迁移产品化。

## RT-003：实现 durable append 与同事务 projector

- Size：M
- Depends on：CON-002、RT-002
- 关联：D-010、路线图技术门
- 目标：证明事件、aggregate seq 和 projection 可在一个事务中提交。
- 交付：append API、optimistic/version check、projector、busy/error handling 和 crash points。
- 验收：crash injection 不出现 committed event 缺 projection 或反向分叉；seq 严格递增；并发 writer 被拒绝或串行化；durability 与基线一致。
- 排除：跨进程多 writer 和 Connector shadow DB。

## RT-004：实现 snapshot、cursor、durable SSE 与 bounded fanout

- Size：M
- Depends on：CON-004、CON-005、RT-003
- 关联：Native Runtime Spike 范围
- 目标：完成可恢复的事件读取与多订阅者分发原型。
- 交付：snapshot、cursor、replay、compaction boundary、durable SSE 和 bounded subscriber queue。
- 验收：golden traces 全部通过；慢订阅者不会撑爆内存或阻塞 writer；100k 恢复和 fanout 可测；断线后从 cursor 收敛。
- 排除：WAN Relay 和 Mobile 专用协议分叉。

## RT-005：执行兼容、崩溃、IPC 与八小时基准

- Size：M
- Depends on：RT-002..004、QA-001
- 关联：路线图 Native Runtime 技术门
- 目标：按 RT-001 预登记规则生成完整原始报告。
- 交付：release binaries、raw measurements、置信区间/分位数、crash results、sidecar IPC wall-clock、RSS/FD/task soak 曲线和环境 manifest。
- 验收：不手工剔除 outlier；兼容和 crash consistency 先通过才评性能；IPC 对完整 mock replay 增量小于 5%；八小时无持续泄漏趋势；报告包含失败结果。
- 排除：营销文案和改变门槛。

## RT-006：形成 Runtime go/no-go ADR 与 Alpha backlog

- Size：S
- Depends on：RT-005
- 关联：D-006、D-014；路线图 4.4、6
- 目标：把实验结果转换为继续、窄化或停止的书面决策。
- 交付：ADR；团队 Rust 维护/on-call 评估；性能门表；若 GO，列出单 Provider、核心工具、隔离 worktree 和 canary 迁移的独立 backlog；若 NO-GO，列出保留的窄优化。
- 验收：产品门与技术门结论分开；没有因为 sunk cost 降低标准；GO 不表示立即替换 Companion；ADR 由技术 DRI 和维护者签字。
- 排除：在本任务实现 Runtime Alpha 产品功能。
