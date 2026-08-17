# Nomad 技术实施计划

| 字段 | 内容 |
| --- | --- |
| 状态 | Proposed 0.1 |
| 日期 | 2026-08-17 |
| 目标 | 将技术架构转成可并行分配、可独立验收、可留下证据的原子任务 |
| 当前约束 | 本文只规划，不代表已开始实现 |

## 1. 实施策略

实施分为三条结论独立的轨道：

1. Validation Companion：验证跨端产品闭环，是主产品关键路径。
2. Security Architecture：决定何时可接触真实仓库和开放远程 allow once，是硬门。
3. Native Runtime Spike：验证 Rust Session/Event 内核是否值得，是条件式旁路。

三条轨道共同依赖 Session Semantics v0，但产品门、技术门和安全门分别记录，任何一门不能替另一门背书。

## 2. 原子任务规则

每个任务必须满足：

- 一个明确 owner；默认一个任务对应一个分支和一个聚焦 PR。
- 只产生一个主要能力或一个决策证据，预计可由单个 agent 在一个短开发周期内完成。
- 有可机器验证的验收条件；纯研究任务必须有冻结的输入、对照方案和书面结论。
- 明确写出不做什么，防止 agent 顺手扩范围。
- 修改共享 contract 时由 contract owner 合入，消费方不得各自发明协议字段。
- 安全或产品降级属于合法结果。例如 OpenCode permission spike 失败时，输出应是“关闭 allow once”的证据，而不是强行实现。
- 任务完成不等于阶段完成；阶段门按产品文档要求的累计证据判断。

建议任务规模：

- `S`：单一类型、接口或测试夹具。
- `M`：一个纵向能力，包含实现与测试。
- 超过 `M` 的任务必须再次拆分。

## 3. 所有权分区

| Lane | 独占或主要目录 | 可以并行的责任 |
| --- | --- | --- |
| Contract | `contracts/` | schema、golden traces、conformance |
| Host | `connector/` | OpenCode adapter、projection、command、diff、CLI |
| Relay | `relay/` | WSS、mailbox、pairing、Push、retention |
| Mobile | `mobile/` | reducer、UI、secure storage、Push/lifecycle |
| Security | `docs/technical/adr/`、安全向 test vectors | threat model、envelope、approval policy |
| Quality | `testkit/`、CI 配置 | fake server、fault injection、E2E、性能与安全回归 |
| Runtime Spike | `runtime-spike/` | Rust 原型与基准，不修改 Companion 主路径 |

跨 lane 接口通过 versioned contract 和测试向量交付，不通过复制内部类型交付。若一个任务必须同时修改两个 lane，应拆成“生产 contract”和“消费 contract”两个任务。

## 4. 阶段门与依赖图

```text
                    +----------------------+
                    | G0 DRI / scope ready |
                    +----------+-----------+
                               |
                   +-----------v------------+
                   | G1 Session Semantics v0|
                   +------+------------+----+
                          |            |
             +------------v--+      +--v----------------+
             | Companion Spike|      | Runtime Spike     |
             | Host/Relay/iOS |      | Rust benchmark    |
             +--------+-------+      +---------+---------+
                      |                        |
             +--------v---------+              v
             | Adapter product  |       independent
             | gate             |       go / no-go
             +--------+---------+
                      |
        +-------------v----------------+
        | G2 Security Architecture     |
        | + Security Envelope v0       |
        +-------------+----------------+
                      |
        +-------------v----------------+
        | Companion Internal Alpha     |
        | integration / fault / release|
        +-------------+----------------+
                      |
        +-------------v----------------+
        | G3 Private Alpha release gate|
        +------------------------------+
```

`G0` 是组织前置，不是编程任务：产品、技术、安全 DRI 必须登记；固定 OpenCode 版本、支持平台和“本轮不实现 Runtime 产品化”必须再次确认。

## 5. 建议并行波次

| 波次 | 可并行任务组 | 合流条件 |
| --- | --- | --- |
| W1 语义与证据 | `CON-001..005`、`QA-001`、`SEC-001`、`RT-001`、`HC-001` | Session Semantics v0 评审通过；技术 spike 输入固定 |
| W2 技术决策 | `HC-002`、`MB-001`、`RL-001`、`SEC-002..003`、`RT-002..004`、`OPS-003` | 长期栈、信任模型与共享 contract 有书面结论 |
| W3 垂直骨架 | `HC-003..006`、`HC-009`、`HC-011`、`RL-002..006`、`RL-009`、`MB-002..005`、`MB-014`、`QA-002` | Host、Relay、Mobile 能用同一 contract 完成只读同步与恢复 |
| W4 核心交互与安全 | `HC-007..010`、`HC-012..013`、`HC-015`、`RL-007`、`MB-006..012`、`SEC-004..005`、`QA-003..004`、`OPS-001..002`、`OPS-004` | 查看、reply、deny、Stop、diff、条件式 allow 与安全回归闭环 |
| W5 发布合流 | `HC-014`、`HC-016`、`RL-008`、`RL-010`、`MB-013`、`MB-015`、`QA-005..006`、修复任务 | PRD 第 13 节发布门逐项有证据 |
| W-R 条件 Runtime | `RT-005..006` | 独立技术门结论，不阻塞 W1-W5 |

波次是规划分组，不是所有任务同时开工的许可；组内仍严格遵守每张任务卡的依赖。

## 6. 任务索引

| 文档 | 任务范围 | 数量 |
| --- | --- | ---: |
| [基础协议与安全](tasks/01-contract-security.md) | Session Semantics、安全架构、Envelope、测试资产 | 10 |
| [Host Connector](tasks/02-host-connector.md) | 固定 OpenCode adapter、投影、命令、diff、CLI、生命周期与制品 | 16 |
| [Secure Relay](tasks/03-secure-relay.md) | gateway、opaque mailbox、账户、配对、设备、Push、retention 与部署 | 10 |
| [Mobile Companion](tasks/04-mobile-companion.md) | 技术栈 spike、账户、同步、状态 UI、交互、安全与无障碍 | 15 |
| [质量、发布与运维](tasks/05-quality-operations.md) | conformance、故障注入、E2E、安全、性能、制品、仓库骨架和分析 | 10 |
| [Native Runtime Spike](tasks/06-runtime-spike.md) | 条件式 Rust Session/Event 内核与基准 | 6 |

共 67 个原子任务。任务数量服务于接口隔离和并行开发，不代表所有任务都必须在同一个阶段启动。

## 7. 关键合流点

### 7.1 Session Semantics v0

进入 Host、Relay 和 Mobile 正式消费前，必须具备：

- 版本化 schema。
- 状态不变量。
- 至少覆盖普通完成、reply、Stop、permission、断线恢复和 `OutcomeUnknown` 的 golden traces。
- 未知字段、未知事件、旧客户端和新客户端的兼容策略。
- 跨语言 conformance runner。

### 7.2 OpenCode Adapter 阻断结论

必须独立证明固定版本是否能：

- 保持同一个 upstream pending permission。
- 读取完整原始输入并稳定绑定。
- 在 Mobile/Desktop 竞争时只接受一个终态。
- Connector 断线、参数变化和无法确认时 fail closed。

任一不满足就关闭 Mobile allow once，后续任务只实现查看、deny 和 Stop。

### 7.3 Security Architecture

在真实仓库和可写远程审批前必须形成 Accepted ADR，覆盖：

- 账户、Host、Mobile 和 Relay 的信任模型。
- 设备加入、吊销、key epoch 和历史密文。
- 无密钥恢复行为。
- Security Envelope v0 和成熟密码库选择。
- 远程 allowlist。

### 7.4 Private Alpha 发布证据

合流负责人维护 PRD 第 13 节 checklist。任务 PR 只提供可引用证据，不在各自 PR 中宣称系统已达 Private Alpha。

## 8. Agent 分配协议

给开发 agent 的任务提示至少包含：

```text
任务 ID 与任务卡路径：
目标分支/工作区：
允许修改的目录：
禁止修改的目录：
已冻结的 contract/ADR 版本：
前置依赖 commit：
要求执行的验证：
完成后填写的留痕文件：
```

并行执行约束：

- 每个 agent 使用独立分支或 worktree。
- Contract、migration、CI 根配置和依赖锁文件设单一 merge owner。
- Agent 不回滚或格式化其他 lane 的未合入工作。
- 发现 contract 缺口时先提交 issue/ADR 或兼容测试，不在消费端添加私有字段。
- 发现安全不变量无法满足时停止相关高风险能力，保留最小复现和证据。

## 9. 完成定义

单个任务只有同时满足以下条件才是 `Done`：

- 验收条件全部通过。
- 自动测试和任务指定的手工验证有结果。
- 没有扩大任务的 `Out of scope`。
- 接口、数据迁移、安全或运维行为变化已更新相应 ADR/文档。
- 完成留痕包含 commit/PR、验证证据、偏差、风险和后续任务。
- 新发现的问题有独立任务 ID，不用 TODO 隐藏。
