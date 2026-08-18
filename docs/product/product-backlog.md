# Nomad 产品需求池

| 字段 | 内容 |
| --- | --- |
| 状态 | Proposed |
| 更新日期 | 2026-08-18 |
| 候选迭代 | Controlled Pilot v0.2，待 M0 评审确认 |
| 优先级方法 | Hard gate + MoSCoW + RICE |
| 执行状态 | Funnel / Ready / In Progress / Validate / Done / Blocked / Dropped |

## 1. 使用规则

- 本表的 `PRD-*` 是产品需求唯一索引；技术任务可以多对一关联，不得另造产品范围。
- 安全、状态正确性和 Pilot 闭环是 hard gate，不因 RICE 分数较低而后移。
- RICE 只做同一阶段内的相对排序：`Reach × Impact × Confidence / Effort`。Reach 是本轮可影响的 10 名 Pilot 用户或 15 名研究对象，Impact 使用 0.5/1/2/3，Effort 使用人周。
- Owner 在 M0 必须替换成具体人名；角色占位不能进入 In Progress。
- `Done` 要求代码/研究、验收证据、指标和文档状态同时完成。

## 2. 候选迭代需求总表

| ID | Epic | 用户结果 / 需求 | MoSCoW | RICE | 状态 | Owner | 关键依赖 | 验收证据 |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| PRD-201 | Discovery | 证明离桌阻塞的频率、成本和现有 workaround | Must | 45.0 | Ready | 产品/研究 | 招募渠道 | 15 次访谈、8 人日记、H1 判定 |
| PRD-202 | Discovery | 验证结构化 UI 相对移动终端的理解与偏好 | Must | 24.0 | Ready | 设计/研究 | PRD-201 样本 | 12 人任务测试、H2/H3 判定 |
| PRD-203 | Onboarding | 在 30 秒内完成环境预检并给出可行动错误 | Must | 16.0 | Funnel | Host | 固定版本 | 干净机预检记录、错误码矩阵 |
| PRD-204 | Pairing | 无主持完成一次性扫码和两端比对 | Must | 18.0 | Funnel | Host/Mobile | 测试身份模型 | 10 人配对结果、重放/过期测试 |
| PRD-205 | Live Adapter | 投影固定 OpenCode 的真实 Session 事实 | Must | 15.0 | Funnel | Host/架构 | AR-01、固定版本 | 五类真实 capture、provenance、conformance |
| PRD-206 | Command | reply 被同一真实 Session 最多接纳一次 | Must | 18.0 | Funnel | Host/Mobile | PRD-205 | request 重试测试、Host 结果 |
| PRD-207 | Command | deny 解决同一个 upstream pending；不创建第二套状态 | Must | 12.0 | Funnel | Host | PRD-205、HC-009 边界 | 真实 pending/竞争测试 |
| PRD-208 | Command | Stop 的 received、accepted、cancelled 分层可信 | Must | 18.0 | Funnel | Host/Mobile | PRD-205 | 真实 Stop 流程、重复请求测试 |
| PRD-209 | Safety | Pilot 全链路关闭 allow_once 并可验证 | Must | Hard gate | Ready | 安全/Host | HC-009 No-Go | UI absence、Host rejection、合同测试 |
| PRD-210 | Home | 用户 10 秒内判断是否需要自己和最后进展 | Must | 14.4 | Funnel | 设计/Mobile | PRD-205 | 任务测试成功率、时间 |
| PRD-211 | Timeline | 把协议事件翻译成任务进展，技术字段默认折叠 | Must | 9.0 | Funnel | 设计/Mobile | PRD-205 | 可用性测试、信息映射表 |
| PRD-212 | State | 用户正确理解 Online/Offline 与 Live/Stale | Must | 18.0 | Ready | 设计/Mobile | Session Semantics v0 | 状态辨识率 ≥90%、命令门测试 |
| PRD-213 | Approval | 展示真实 Host 事实并仅提供 deny/Stop | Must | 10.0 | Funnel | Host/Mobile | PRD-205、PRD-207 | 真实工具输入、cwd、过期状态 |
| PRD-214 | Changes | 只展示权威 workspace diff，禁止示例回退 | Must | 12.0 | Funnel | Host/Mobile | AR-03 | 基线/失效测试、用户任务结果 |
| PRD-215 | Recovery | Relay 重启后恢复 Live，无重复接纳和未知 gap | Must | 10.0 | Funnel | Relay/Host/QA | AR-04 | 预登记真实进程重启记录 |
| PRD-216 | Diagnostics | 用户获得可行动诊断，诊断包不含内容 | Must | 8.0 | Funnel | Host/QA | 错误分类 | doctor 覆盖矩阵、内容扫描 |
| PRD-217 | Analytics | 还原 Pilot 漏斗、命令阶段和恢复结果 | Must | 12.0 | Funnel | 产品/QA | AR-05 | 事件字典、禁用字段扫描、看板 |
| PRD-218 | Cleanup | 参与者可清理临时账户、状态和设备绑定 | Must | 6.0 | Funnel | Host/Relay | PRD-204 | 清理脚本/流程、删除记录 |
| PRD-219 | Research Ops | 首批 3 人后分批扩至 10 人并形成计分卡 | Must | 15.0 | Funnel | 产品/研究 | PRD-201..218、PRD-225 | 10 份个体记录、汇总结论 |
| PRD-225 | Pilot Security | 形成只适用于可丢弃外部 Pilot 的安全说明与停止条件 | Must | Hard gate | Funnel | 安全 | AR-02、PRD-204/217/218 | 安全 DRI 接受的 Pilot Security Note |
| PRD-220 | Security ADR | 冻结 SEC-002/003 信任、加入、吊销和 envelope 设计 | Could | 5.0 | Funnel | 安全/架构 | SEC-001 | Accepted/Rejected ADR 与评审记录 |
| PRD-221 | Runtime | 执行 RT-005 并产出 RT-006 决策 | Could | 2.5 | Funnel | 技术 | RT-001 | 原始基准、方差、GO/NO-GO |
| PRD-222 | Native Mobile | 验证 iOS Push/后台/安全存储技术风险 | Could | 3.0 | Funnel | Mobile | PRD-202 | spike 记录，不计 Pilot 价值证据 |
| PRD-223 | Completion | 展示任务完成和测试结果摘要 | Should | 6.0 | Funnel | Host/Mobile | PRD-205 | 真实结果映射、任务测试 |
| PRD-224 | Tech Details | 为诊断提供可折叠协议事件详情 | Should | 3.0 | Funnel | Mobile | PRD-211 | 默认折叠、可复制诊断 ID |

## 3. Epic 说明与用户故事

### RICE 计算底稿

| ID | Reach | Impact | Confidence | Effort（人周） | 计算结果 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PRD-201 | 15 | 3.0 | 100% | 1.0 | 45.0 |
| PRD-202 | 12 | 3.0 | 80% | 1.2 | 24.0 |
| PRD-203 | 10 | 2.0 | 80% | 1.0 | 16.0 |
| PRD-204 | 10 | 3.0 | 90% | 1.5 | 18.0 |
| PRD-205 | 10 | 3.0 | 75% | 1.5 | 15.0 |
| PRD-206 | 10 | 3.0 | 90% | 1.5 | 18.0 |
| PRD-207 | 10 | 3.0 | 60% | 1.5 | 12.0 |
| PRD-208 | 10 | 3.0 | 90% | 1.5 | 18.0 |
| PRD-210 | 10 | 3.0 | 80% | 1.67 | 14.4 |
| PRD-211 | 10 | 2.0 | 90% | 2.0 | 9.0 |
| PRD-212 | 10 | 3.0 | 90% | 1.5 | 18.0 |
| PRD-213 | 10 | 3.0 | 50% | 1.5 | 10.0 |
| PRD-214 | 10 | 3.0 | 80% | 2.0 | 12.0 |
| PRD-215 | 10 | 3.0 | 50% | 1.5 | 10.0 |
| PRD-216 | 10 | 2.0 | 80% | 2.0 | 8.0 |
| PRD-217 | 10 | 2.0 | 60% | 1.0 | 12.0 |
| PRD-218 | 10 | 1.0 | 60% | 1.0 | 6.0 |
| PRD-219 | 10 | 3.0 | 75% | 1.5 | 15.0 |
| PRD-220 | 10 | 3.0 | 50% | 3.0 | 5.0 |
| PRD-221 | 10 | 1.0 | 50% | 2.0 | 2.5 |
| PRD-222 | 10 | 1.0 | 60% | 2.0 | 3.0 |
| PRD-223 | 10 | 1.0 | 60% | 1.0 | 6.0 |
| PRD-224 | 10 | 0.5 | 60% | 1.0 | 3.0 |

PRD-209 和 PRD-225 是安全 hard gate，不以分数参与取舍。RICE 是基于当前信息的容量假设，M0 由实际 Owner 重新估算 Effort；若分数变化但 hard gate 和依赖不变，不改变其阻断关系。

### E1：Discovery 与价值验证

#### PRD-201 问题频率与替代成本

用户故事：作为产品团队，我希望只从真实最近行为中判断离桌阻塞的频率和成本，以便决定是否值得继续建设独立 Companion。

验收：

- 15 个有效访谈分布满足验证计划配额。
- 8 名高频用户记录连续 7 天，而不是补写汇总。
- 每个事件记录任务类型、持续时间、离桌原因、阻塞类型、等待分钟和 workaround。
- 同时保留支持和反对产品的原话。
- 输出 H1：Pass / Fail / Inconclusive，不用“用户觉得很酷”替代。

#### PRD-202 结构化 UI 任务测试

用户故事：作为离桌用户，我希望在小屏上理解任务和风险，而不必阅读原始终端输出。

验收：

- T1-T6 都有无提示任务脚本。
- 关键任务成功率至少 85%；状态辨识至少 90%。
- benign/dangerous 判断错误逐例复盘；高风险误操作一例即停止。
- 至少 70% 参与者选择结构化页面作为默认入口。

### E2：Onboarding 与配对

#### PRD-203 环境预检

用户故事：作为 Pilot 参与者，我希望产品在开始前告诉我环境是否可用，并给出一步可执行的修复。

验收：版本、架构、端口、测试仓库和临时账户逐项显示；失败不泄露路径或凭据；干净环境 30 秒内完成。

#### PRD-204 一次性配对

用户故事：作为参与者，我希望通过扫码和两端比对确认连接的是自己的测试 Host。

验收：单次使用、两分钟过期、双端确认、重放拒绝；至少 9/10 无人工帮助成功。

### E3：真实 Session 与命令

#### PRD-205 固定 OpenCode adapter

用户故事：作为手机用户，我希望看到真实 Agent Session，而不是预录 trace。

验收：

- 真实 capture 覆盖 question、permission、Stop、diff、reconnect。
- 数据标记 captured + 版本 + 测试仓库 commit。
- adapter 不写上游数据库，不把未知事件伪装成已支持状态。
- 同一 capture 通过 conformance runner。

#### PRD-206 / 207 / 208 命令闭环

共同验收：Relay received、Host accepted/rejected、最终状态和后续 progress 分开；重复 request 不重复生效；Offline/Stale 不上传命令。

PRD-207 额外门槛：如果真实 OpenCode 不能保证同一 pending 和竞争裁决，保留 No-Go，Pilot 只展示 permission 并支持 Stop；不得以自建 pending 掩盖。

### E4：移动任务控制面

#### PRD-210 Home

用户故事：作为离桌用户，我希望打开后先看到需要我处理的任务，其次是仍在运行的任务。

验收：不出现 trace loader；10 秒任务判断；状态包含最后活动和明确 CTA。

#### PRD-211 Timeline

用户故事：作为非协议开发者，我希望看到“Agent 在搜索文件/等待回答/测试失败”，而不是事件类型和 seq。

验收：每个支持事件有用户文案、时间、结果和必要上下文；内部字段默认折叠。

#### PRD-212 状态与安全门

验收：Live、Reconnecting、Stale、Offline 各有含义、可用动作和恢复建议；只有 Online + Live 可提交命令。

#### PRD-213 权限事实

验收：展示工具、参数、cwd、已知资源、过期时间、来源；模型说明与 Host 事实视觉分区；Pilot 没有 Allow。

#### PRD-214 权威 Changes

验收：没有 Host diff 时为空态；不允许 SAMPLE_FILES fallback；外部编辑、二进制、超大文件和基线失效显式呈现。

### E5：可靠性、诊断与数据

#### PRD-215 重启恢复

验收：对真实 Host/Relay/Mobile 进程执行可重复重启；30 秒内收敛或保持 Stale；没有重复 Host 接纳。

#### PRD-216 Doctor

验收：覆盖版本不符、Relay 不可达、Host 离线、cursor gap、snapshot mismatch、配对过期；输出诊断 ID 和用户动作。

#### PRD-217 Pilot Analytics

验收：能计算激活、任务成功、帮助次数、命令阶段、恢复和复测意愿；事件 payload 通过禁止字段扫描。

#### PRD-218 清理

验收：测试结束后删除本地 Pilot 状态、临时账户和 Relay 测试绑定；删除结果可确认且幂等。

#### PRD-225 Pilot Security Note

验收：安全 DRI 在邀请外部参与者前书面接受仅适用于可丢弃测试数据的身份、TLS、Relay 访问控制、设备解绑、保留期、事故响应和停止条件；文档明确这不是 D-005 或生产 Security Envelope 的替代证据。

## 4. 依赖图

```text
PRD-201 ──> PRD-202 ──> Problem / Interaction Gate

AR-01 ──> PRD-205 ──┬─> PRD-206 Reply
                     ├─> PRD-207 Deny ──> PRD-213 Approval
                     ├─> PRD-208 Stop
                     ├─> PRD-210/211/212 UI
                     └─> PRD-214 Changes

PRD-204 + PRD-205 + PRD-206..218 + PRD-225 ──> PRD-219 Controlled Pilot

PRD-220 Security ADR ──> Internal Alpha（不阻塞可丢弃 Pilot）
PRD-221 Runtime Decision ──> Runtime Alpha（不阻塞 Companion）
```

## 5. Definition of Ready

需求进入 `Ready` 必须满足：

- 有明确用户结果和不做什么。
- 有 Given/When/Then 或可量化验收。
- 明确数据与隐私影响。
- 依赖 contract/ADR 已冻结或明确 Blocked。
- Owner 是具体人，估算不大于一个短周期；更大则拆分。
- 有测试方法、证据路径和发布/回滚影响。
- 若新增范围，明确替换掉当前迭代的哪项容量。

## 6. Definition of Done

需求标记 `Done` 必须满足：

- 产品验收全部通过，自动与手工证据可复核。
- 错误、空态、弱网、版本不兼容和清理路径已覆盖。
- 需要的埋点已验证且无禁止字段。
- contract、ADR、PRD、任务报告和用户文案已同步。
- 没有把 synthetic/reference 证据写成 live/production 结论。
- 新发现问题有独立 ID、Owner 和优先级。
- 产品 DRI 与对应技术/安全 DRI 签字。

## 7. Icebox

| 需求 | 重新进入条件 |
| --- | --- |
| 移动 allow_once | HC-009 真实 gate 通过 + D-005 Accepted + 独立安全评审 |
| 原生 iOS 产品化 | Controlled Pilot 产品门通过，且 Web 生命周期成为主要阻碍 |
| Android / 第二 Host OS | Closed Beta 前的设备分布和流失数据 |
| 多 Host | 单 Host 留存成立并出现真实切换需求 |
| 远程启动任务 | workspace allowlist、隔离和权限模型成熟 |
| 自有 Runtime | RT-006 GO/CONDITIONAL GO，且不阻塞 Companion |
| 团队策略、SSO、审计 | 至少两个有预算设计伙伴承诺试点 |
| 付费 | Private Alpha 出现持续使用，先验证真实付款 |
