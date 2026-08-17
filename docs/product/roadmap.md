# Nomad 路线图

| 字段 | 内容 |
| --- | --- |
| 状态 | Draft 0.1 |
| 日期 | 2026-08-11 |
| 规划方式 | 阶段门，而不是固定发布日期 |
| 基准团队 | 4 名工程师、1 名产品设计、1 名产品负责人；其中一名工程师担任内部安全 DRI，独立安全顾问按阶段参与 |

## 1. 路线图原则

- 先验证跨端需求，再承诺完整 Runtime。
- 产品验证和 Rust 技术验证并行，但分别做 go/no-go。
- 每个阶段必须交付可由用户完成的闭环，不按组件完成度宣布进展。
- 可靠性和安全缺陷优先于 Provider、工具和界面数量。
- 一旦阶段门不通过，允许保留 companion、保留 Runtime 或终止，不为既有投入继续扩张。

## 2. 阶段总览

时间是基于基准团队的估算。若只有一至两名工程师，应按工作流串行，不应通过削减安全测试维持日期。

| 阶段 | 估算 | 目标 | 主要产物 | 阶段门 |
| --- | --- | --- | --- | --- |
| 0. Problem Discovery | 4 周 | 证明问题频率和移动任务形态 | 访谈、日记研究、可点击原型 | 问题和流程门 |
| 1. Dual Spike | 4 至 6 周，可与阶段 0 后半并行 | 验证移动连接和 Rust 内核，分层冻结共享协议 | Session Semantics v0、OpenCode Companion、Rust benchmark、Security Envelope v0 | 产品、技术和安全三门 |
| 2. Companion Internal Alpha | 6 至 8 周 | 团队内部完成真实跨端任务 | 固定 OpenCode Adapter、Relay、macOS Connector、iOS App | 安全与可靠性门 |
| 2R. Runtime Alpha | 8 至 12 周，与阶段 2 分支进行 | 仅在技术门通过后验证自有 Runtime | 单 Provider、核心工具、隔离 worktree | Runtime 迁移门 |
| 3. Companion Private Alpha | 8 周 | 10 至 30 名设计伙伴连续使用 | Validation Companion P0、诊断和运维能力 | 使用与留存门 |
| 4. Closed Beta | 10 至 12 周 | 60 名以上激活用户后验证比例指标，再逐步扩量 | 第二平台候选、Runtime 迁移候选、计费实验 | 留存与稳定性门 |
| 5. Public Beta | 12 周以上 | 建立公开分发和付费基础 | 开源 Runtime、托管 Relay、文档 | v1 SLA 和商业门 |

## 3. 阶段 0：Problem Discovery

### 目标

确认“离开电脑后推进本机 Agent”是高频、痛苦且现有方案处理不好的问题。避免只访谈对产品概念感兴趣、但实际没有长任务的用户。

### 工作

| 工作流 | 交付物 |
| --- | --- |
| 用户研究 | 招募 20 人，完成至少 15 次情境访谈；主研究 cohort 满足验证计划的高频门槛 |
| 日记研究 | 8 人记录一周内 Agent 等待、离桌、回桌和远程处理事件 |
| 原型 | Home、Session、Approval、Diff、弱网状态的可点击原型 |
| 竞品体验 | Claude/Codex Remote、Happy、OpenCode Web、SSH/tmux 对照记录 |
| 招募 | 建立 10 名 Internal Alpha 和 30 名 Private Alpha 候选池 |

### 退出标准

- 15 人中至少 8 人每周遇到一次离桌后 Agent 等待或无法判断状态。
- 至少 5 人已经使用 SSH、tmux、远控、通知脚本或刻意放宽权限作为替代方案。
- 可用性测试达到验证计划 E2 的唯一通过线，不在路线图重复另一组百分比。
- 至少 10 人愿意安装本地原型并提供一周使用数据。

若达不到，先调整目标用户或问题定义，不进入完整开发。

## 4. 阶段 1：Dual Spike

这个阶段有两条结论独立的轨道，以及一个共同协议交付物。不能用一条轨道的结果替另一条背书，也不能让两条轨道各自发明客户端协议。

### 4.0 共享交付物：Session Semantics v0

进入两个 Spike 的实现前先冻结不依赖信任模型的语义层：

- Session、Turn、Host connectivity 和 Client freshness 的正交状态。
- Durable 与 ephemeral 事件、版本、序号、快照和 cursor。
- Command request ID、Host 接纳、最终结果与 `OutcomeUnknown`。
- Adapter contract、向前/向后兼容范围和未知事件处理。

产品 DRI、技术 DRI、Mobile 和安全 DRI 共同签字。之后的字段变更必须更新 Semantics version 和 golden trace。加密 envelope、sender/recipient、key version、签名覆盖范围、设备加入和轮换字段不能在信任模型之前冻结，它们由 4.3 安全架构门产出 Security Envelope v0。

### 4.1 Mobile Bridge Spike

使用 OpenCode 的本地 HTTP/SSE 能力快速打通：

```text
OpenCode local server
→ Host connector
→ encrypted test relay
→ mobile prototype
```

先进行内部技术验证：

- 扫码配对一台主机。
- 查看正在运行的 Session 和结构化事件。
- 展示合成 permission，发送一条消息，执行 Stop。安全门前只允许 deny/Stop，不允许手机发送 allow。
- 查看当前 diff。
- Wi-Fi 与蜂窝网络切换后恢复。
- 通用 Push 唤醒。

内部验证只使用团队成员和无敏感信息的合成仓库。Spike 固定 Apple Silicon macOS、iOS 和一个 OpenCode 版本。可以接受简化账户、单区域和测试证书，但不能跳过事件序号、Host 接纳去重和 `OutcomeUnknown`。

Adapter 阻断验证：

- OpenCode 创建唯一 pending permission 和 upstream permission ID，Connector 不创建第二套 pending 状态。
- Connector 能读取并绑定原始工具输入，在手机决定返回前保持同一 pending request。
- 手机和桌面竞争处理时，OpenCode 只接受一个终态；Connector 能从事件或快照确认胜出结果。
- Connector 掉线、版本不匹配、action hash 变化或结果不可确认时 fail closed，不发送 allow。
- 若固定 OpenCode 版本不能满足以上任一项，Validation Companion 的移动权限能力永久降为查看、deny 和 Stop，直到自有 Runtime 通过迁移门。

Adapter 内部验证完成后，可以让 10 名外部候选参加 Controlled Product Pilot。Pilot 只使用项目提供的可丢弃测试仓库和临时账户，允许查看、reply、deny 和 Stop，不开放移动“允许一次”，也不接触用户真实代码。它验证安装、配对、交互理解和重复使用意愿，不代表真实工作流留存。

Controlled Product Pilot 的产品门：

- 10 名候选用户中至少 8 人完成安装、配对和一次由 Host 接纳的 reply、deny 或 Stop。
- 至少 5 人愿意在一周内参加第二次无主持测试；这只作为继续验证信号，不计留存。
- 测试任务完成率达到验证计划 E2/E4 的门槛。
- 用户更偏好结构化页面，而不是要求默认打开 raw terminal。

### 4.2 Native Runtime Spike

固定一个 OpenCode 发布版本作为行为与性能基线，Rust 只实现最小 Session/Event 内核：

- SQLite schema 和只读 Session/message/history。
- Durable event append、seq 和同事务 projector。
- Snapshot 加游标恢复。
- SSE fanout 和 bounded queue。
- Permission matcher 只做 parity，不接管真实执行。

技术门：

- Schema、事件、游标、错误和投影 golden test 100% 通过。
- Crash injection 不出现 committed event 缺投影或反向分叉。
- 实验前登记 3 至 5 个产品 workload、权重和非退化预算；至少一个用户关键 workload 提升 2 倍或峰值 RSS 下降 40%，其余关键 workload 不超过预算。
- Sidecar IPC 给完整 mock Agent replay 增加的墙钟时间少于 5%。
- 八小时 soak 无持续 RSS、FD 或任务泄漏。

若技术门不通过，停止重写并继续用成熟 Runtime 做产品验证。不得为了保留 Rust 叙事降低基准。

### 4.3 安全架构门与 Security Envelope v0

D-005 在合成仓库的内部验证和 Controlled Product Pilot 期间可保持 `Proposed`，但团队真实仓库测试和任何外部用户接触真实仓库、真实 Session 内容或可写远程审批前必须转为 `Accepted`。安全架构门至少冻结：

- 账户身份、Host 身份和信任根。
- 新设备如何由已有可信端授权。
- 历史密文访问范围和设备吊销后的密钥轮换。
- 全部可信设备丢失后的行为。Validation Companion 明确不恢复 Relay 历史。
- Relay、APNs、模型 Provider 和遥测各自的数据边界与保留期。
- 手机可批准工具 allowlist，以及任意 shell 必须回桌面的规则。
- Security Envelope v0：sender/recipient、key version、签名和 action hash 覆盖范围、replay protection 与版本协商。

安全门不通过时只能继续合成或可丢弃测试仓库，不能使用团队真实仓库，也不能进入外部 Private Alpha。

### 4.4 三门决策

| 产品门 | 技术门 | 决定 |
| --- | --- | --- |
| 通过 | 通过 | Companion 进入阶段 2；Runtime 进入独立阶段 2R，通过迁移门前不替换 Companion |
| 通过 | 不通过 | Companion 进入阶段 2，停止全面重写，只保留经 profiling 证明的窄优化 |
| 不通过 | 通过 | 可保留开源 Runtime 项目，停止移动产品扩张 |
| 不通过 | 不通过 | 停止项目或重新定义问题 |

安全门是外部发布的附加硬门，不改变上表对产品与技术投资的判断。

## 5. 阶段 2：Companion Internal Alpha

### 目标

安全架构门通过后，让团队成员用受支持的 OpenCode 版本处理真实仓库，并在手机上完成一次允许远程处理的阻塞。这个阶段不追求外观完整，追求状态准确。安全门未通过时只能使用可丢弃仓库，不能开始本阶段的退出计数。

### Host Connector 工作流

- 固定 OpenCode 版本、loopback Server 和 Adapter golden trace。
- Apple Silicon macOS 安装、签名、升级、卸载和 `nomad doctor`。
- Workspace 基线、外部变化检测和无法归因标识。
- 活跃任务可选阻止自动睡眠，合盖和手动睡眠提示。
- Bounded tool/event projection，不创建第二个 Session writer。

### Cross-device 工作流

- Host daemon、出站 WSS、事件 seq、snapshot reconcile。
- 设备身份、二维码配对、单设备吊销。
- E2EE、Push、密文短期补发。
- Approval action hash、Host 接纳去重、`OutcomeUnknown`、message 和 Stop。
- 无密钥恢复的设备加入、吊销和密钥轮换。
- Relay 和 Host 的基础 metrics、trace 和诊断。

### Mobile 工作流

- Home、Session、Approval、Changes、Devices。
- iOS 前台流、后台 Push、自动锁。
- 大列表和大 diff 性能。
- VoiceOver 基础支持。

### 退出标准

- 团队完成至少 100 个真实 Session 和 50 次跨端操作。
- 连续两周没有丢失持久事件、错误绑定审批或同一 request 启动两次。
- Apple Silicon macOS 和 iOS P0 流程全部通过。
- 通过 threat model 中的配对、重放、Relay 入侵和手机丢失演练。
- 10 名友好用户可以在不由开发者现场协助的情况下完成安装和配对。

## 6. 阶段 2R：Runtime Alpha

### 启动条件

只在 Native Runtime Spike 的预登记基准、兼容和团队维护能力全部通过后启动。它与 Companion Internal Alpha 并行但独立，不进入阶段 2 的关键路径。

### 范围

- 一个由设计伙伴使用分布决定的 Provider 路径。
- `read`、`glob`、`grep`、精确文件 edit 和受限直接进程工具。
- Session/Event 唯一 writer、同事务 projection、resume、abort 和 compact。
- 每个可写 Session 使用隔离 worktree，避免把用户或其他 Session 的改动归因给 Agent。
- Session Semantics v0 adapter，使 Mobile 不感知底层是 OpenCode 还是 Nomad Runtime；跨网继续使用 Security Envelope v0。
- Apple Silicon macOS 单平台；无插件、MCP、LSP、ACP、完整 TUI 或第二 Provider。

### 迁移门

- 使用同一任务 corpus 时，Protocol 行为与 Companion golden trace 兼容。
- 100 个内部真实 Session 中没有数据损坏、并发可写 Turn 或未知自动重跑。
- 用户关键性能 workload 达到预登记门槛，其他 workload 未超退化预算。
- 对开发吞吐、故障处理和发布成本的评审通过。
- 仅在单独 canary cohort 中启用，不就地迁移所有 Companion 用户。

## 7. 阶段 3：Companion Private Alpha

### 目标

验证用户会不会形成习惯，同时把内部可诊断的系统变成外部可用的产品。

这是第一个允许外部用户连接真实仓库并对 allowlist 操作选择“允许一次”的阶段。开始前必须先完成 Companion Internal Alpha 退出标准和 Validation Companion PRD 第 13 节全部外部发布门。

### 产品范围

- 完成 Validation Companion PRD 全部 P0。是否使用自有 Runtime 不影响该产品门。
- 设备、Session 和通知设置。
- 安装器、自动更新、卸载和数据删除。
- `nomad doctor` 和用户可预览的诊断包。
- 受控 feature flag 和快速回滚。
- 支持团队在用户明确同意后查看化名化可靠性指标，不读取 Session 内容。

### 运营方式

- 10 人起步，每周增加 5 人，不一次性放量。
- 每周固定 office hour 和五次短访谈。
- 所有安全、恢复和数据损坏问题进入每日 triage。
- 每名用户明确知道产品不会在电脑关机后继续运行。

### 退出标准

- 至少 30 名合格用户完成本地 Session，20 名完成跨端闭环。
- 20 名跨端激活用户中至少 8 名第 4 周仍完成远程推进或止损，并访谈所有流失用户。
- 至少 20 个合格 Permission 或 Question 中，16 个不需回电脑解决。
- 可靠性按 PRD 分别报告故障注入样本、真实恢复次数和 Crash 原始次数。
- 没有 Security Critical/High/Medium 事故或未修复漏洞；缺陷分级和接受规则以 PRD 第 13 节为准。
- 至少 10 名用户明确表示产品移除后会明显失望或退回繁琐 workaround。

## 8. 阶段 4：Closed Beta

### 目标

在更大设备和网络矩阵上验证留存、运行成本与付费意愿。

### 候选范围

- 根据 Discovery 和流失数据选择 Android 或第二 Host OS，只增加一个平台维度。
- MCP stdio、附件和 Session 导出。
- 预批准 workspace 的远程任务发起，小规模实验。
- 自托管中继技术预览。
- 多主机、通知日程和更完整的设备恢复。
- 付费计划和十四天 Pro 试用，不限制本地 Runtime。

### 退出标准

- 100 至 300 名月活测试用户。
- 累计至少 60 名跨端激活用户后，第 4 周留存目标 45%，第 8 周目标 30%；同时报告置信区间和绝对人数。
- 付费实验中至少 10% 的合格活跃用户愿意支付真实费用，或设计伙伴签署团队试点。
- Crash-free Session 至少 99.8%；自动故障注入恢复在足量预登记样本中至少 99.5%，真实恢复继续报告原始次数。
- Relay 单位活跃用户成本与候选价格相容。
- 独立安全测试完成，Security Critical/High/Medium 清零。

## 9. 阶段 5：Public Beta 与 v1

### Public Beta 共用范围

- 托管 Relay、Push、计费和支持体系。
- 发布 Session Protocol SDK 和自托管 Relay 文档。
- 稳定升级、缓存迁移、备份和降级政策。
- 保持 Closed Beta 已验证的平台，每个后续阶段最多增加一个平台维度，不承诺一次补齐全部桌面和移动平台。
- Status page、事故响应、漏洞披露和 release signing。

底层实现按 Runtime 迁移门分支：

| Runtime 迁移门 | Public Beta 产物 |
| --- | --- |
| 通过 | 发布自有 Runtime、CLI 和数据迁移政策；Companion 作为迁移和兼容路径保留 |
| 未通过或已停止 | 发布固定支持版本的 OpenCode Companion、Protocol SDK 和 Relay；自有 Runtime 延后或取消 |

### v1 候选门槛

- 最近八周无跨会话审批、同一 request 启动两次或 Nomad 数据边界内的内容泄露事故。
- 关键 API 和 Session 格式有版本与兼容政策。
- 数据迁移和恢复演练覆盖最近三个稳定版本。
- 托管连接有公开 SLO，自托管路径有完整运维说明。
- 付费留存和支持成本可持续。
- 产品定位仍以跨端本机 Agent 为核心，没有被 Provider 或云 runner 功能稀释。

## 10. 工作流与人员

### 10.1 基准团队

| 角色 | 人数 | 主要责任 |
| --- | ---: | --- |
| Host/Runtime 工程师 | 2 | OpenCode Connector；技术门通过后由其中一人进入 Runtime Alpha |
| Relay/Protocol 工程师 | 1 | 事件协议、E2EE、Relay、Push、可观测性 |
| Mobile 工程师 | 1 | iOS、Diff、Push、系统安全能力 |
| 产品设计 | 1 | 研究、交互、移动视觉、可用性与无障碍 |
| 产品负责人 | 1 | 招募、范围、指标、发布和商业验证 |
| 安全 DRI | 由工程师兼任 | 安全阶段门、Threat model 和停止扩量权 |
| 独立安全顾问 | 按需 | Crypto review 和渗透测试，不代替内部责任人 |

若团队只有四人，产品负责人和设计可由一人承担，但 Security review 不能取消。若只有两名工程师，先完成 OpenCode companion；自有 Runtime 必须延后。

### 10.2 决策责任

| 决策 | 负责人 | 必须参与 |
| --- | --- | --- |
| MVP 范围和用户门槛 | 产品负责人 | 技术负责人、设计 |
| 语义协议和持久化 | 技术负责人 | Host/Runtime、Relay、Mobile |
| Security Envelope 和远程权限 | 安全负责人 | 技术负责人、Relay、Mobile |
| 权限与加密 | 安全负责人 | 技术负责人、产品负责人 |
| 移动端交互 | 产品设计 | Mobile、用户研究 |
| 发布与回滚 | 技术负责人 | 全体工程、产品负责人 |
| 阶段 go/no-go | 产品负责人 | 技术负责人，需保留书面分歧 |

## 11. 依赖与关键路径

关键路径不是 TUI 或模型接入，而是：

```text
Session Semantics v0 冻结
→ OpenCode Adapter 与 Host 接纳去重
→ 安全架构门与 Security Envelope v0
→ Host/Relay 恢复协议
→ Mobile 状态与审批
→ 弱网和竞争测试
→ 外部用户
```

主要依赖如下：

| 依赖 | 风险 | 应对 |
| --- | --- | --- |
| APNs 或 Expo Push | 延迟、重复、平台政策 | Push 只唤醒，不作为状态事实；App 回执和前台校准另测 |
| 模型 Provider | 选定上下文会离开本机，且受第三方条款约束 | 首次连接明确披露；Connector 不接管 Provider 凭据 |
| SQLite | 仅 Runtime Alpha 有跨进程写入和迁移风险 | Runtime 成为唯一 writer 前只写 shadow DB |
| OpenCode adapter | 上游接口快速变化 | 固定版本贯穿 Validation Companion，不追随最新版 |
| 移动商店测试分发 | 审核和权限说明 | 提前准备隐私声明，内部渠道先行 |
| 加密库和安全评审 | 稀缺专家资源 | 阶段 1 就预约，不在发布前临时补 |

## 12. 风险登记

| 风险 | 概率 | 影响 | 触发信号 | 应对 |
| --- | --- | --- | --- | --- |
| 用户只需要完成通知，不需要完整 companion | 中 | 高 | 回复、审批、diff 使用率低 | 收缩移动功能或转向通知插件 |
| Claude/Codex 第一方远控覆盖主要用户 | 高 | 高 | 用户不愿为模型无关迁移 | 聚焦 OpenCode/BYOK/企业自托管人群 |
| 自有 Runtime 开发吞噬产品验证 | 高 | 高 | 数月无外部可用闭环 | 双轨验证，技术门不通过就用 adapter |
| Rust 没有显著用户收益 | 中 | 中高 | 基准未过、维护速度慢 | 保留成熟 Runtime，停止重写 |
| 移动审批发生安全事故 | 中 | 极高 | action mismatch、replay、误触 | Fail closed、本机复核、独立安全测试 |
| E2EE 导致恢复和 Web 能力复杂 | 高 | 中高 | 设备丢失后无法恢复、支持量高 | 明确恢复模型，首版减少 Web 和分享 |
| Relay 成本或跨区延迟失控 | 中 | 中 | 大 tool output、长历史、跨洲 P95 高 | bounded output、短期 retention、区域路由 |
| App 后台和 Push 不可靠 | 中 | 高 | 权限请求通知漏达 | 前台 WSS、Push 重试、桌面 fallback |
| 模型能力成为体验瓶颈 | 高 | 中 | 本地很快但任务质量低 | Companion 沿用 OpenCode Provider；Runtime Alpha 只实现一个主路径 |
| 开源与商业边界不清 | 中 | 中 | 社区不信任或托管难收费 | Public Beta 前冻结许可和开放范围 |

## 13. 每阶段都不变的质量条款

- 安全问题不以“测试版”作为降级理由。
- 未通过恢复校验的客户端不得显示 Live。
- 未收到 Host 确认的操作不得显示已执行。
- 不收集内容来换取更快诊断。
- 每次发布都保留上一稳定版本和数据恢复方式。
- 任何跨会话审批、Host 接纳动作与展示不一致或同一 request 启动两次，立即停止扩量。
