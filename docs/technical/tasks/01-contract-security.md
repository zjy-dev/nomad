# 基础协议与安全任务

本组任务由 Contract owner 和 Security owner 主导。除非任务明确说明，消费方只能使用已发布 contract，不得直接修改本目录对应的实现产物。

## CON-001：定义 Session Semantics v0 核心模型

- Size：M
- Depends on：G0（DRI、固定平台和固定 OpenCode 版本登记）
- 关联：D-002、D-004、D-016；PRD 6
- 目标：冻结与信任模型无关的 Session、Turn、连接和新鲜度语义。
- 交付：语言中立 schema；ID、时间、版本规则；三组正交状态；状态转换表；未知状态策略。
- 验收：schema 可生成或校验样例；状态表覆盖 PRD 全部状态；`Completed` 不被误作 Session 终态；评审人包含 Host、Relay、Mobile、安全 DRI。
- 排除：事件 payload、加密字段、传输 frame、具体编程语言类型。
- 留痕重点：Semantics version、评审结论、未解决的兼容问题。

## CON-002：定义 durable/ephemeral 事件 contract

- Size：M
- Depends on：CON-001
- 关联：PRD 6.2、SP-01、SP-06
- 目标：定义可恢复事实与可丢失实时增量的边界。
- 交付：持久事件目录和最小 payload；`event_id`/`seq` 规则；ephemeral 分类；bounded payload/chunk 引用；未知事件策略。
- 验收：PRD 中全部持久事件有 schema；delta 丢失仍可由 durable event 得到最终结果；同一 Session 的 seq 规则可机器验证；内容限制有明确错误。
- 排除：OpenCode 到事件的映射、Mobile UI 呈现和加密 envelope。
- 留痕重点：新增/删除事件的兼容影响和 contract diff。

## CON-003：定义跨端命令与接纳生命周期

- Size：M
- Depends on：CON-001
- 关联：D-016；PRD SP-03、MB-05
- 目标：区分客户端发送、Relay 收到、Host 接纳和最终结果。
- 交付：reply、Stop、interrupt-and-send、permission decision 的 request/result schema；`request_id` 去重规则；错误码；`OutcomeUnknown` 语义。
- 验收：重复 request 返回稳定结果且不产生第二次 Host 接纳；Relay ACK 不能映射成 Host accepted；所有命令都有 expired/stale/incompatible/revoked 拒绝结果；未知副作用明确禁止自动重跑。
- 排除：具体 Host 执行实现和风险 allowlist。
- 留痕重点：命令状态机和崩溃窗口说明。

## CON-004：定义 snapshot、cursor 与恢复协议

- Size：M
- Depends on：CON-001、CON-002
- 关联：PRD SP-02；Validation 6.2
- 目标：让客户端在断线、compaction 和版本变化后确定性收敛。
- 交付：snapshot schema、digest、`last_applied_seq`、resume request/result、gap 与 compaction boundary 规则。
- 验收：覆盖纯增量、重复事件、未知 gap、超出 retention、snapshot 替换和版本不兼容；只有 reducer 与 snapshot 一致才允许 Live；属性测试模型经评审。
- 排除：Relay mailbox 和 Mobile 本地数据库实现。
- 留痕重点：恢复不变量及无法恢复时的明确降级。

## CON-005：建立 golden traces 与 conformance corpus

- Size：M
- Depends on：CON-002、CON-003、CON-004
- 关联：路线图 4.0；PRD HC-02
- 目标：以实现无关证据约束 Host、Mobile 和未来 Runtime。
- 交付：版本化 trace，至少覆盖正常完成、reply、Stop、permission 竞争、重连、compaction、版本错误和 `OutcomeUnknown`；expected snapshots；manifest。
- 验收：每个 trace 有输入、预期事件序列和终态；至少两个独立 reducer 实现或 reference runner 得到同一结果；corpus 变更可在 CI 中展示语义 diff。
- 排除：真实 OpenCode fixture 和网络故障注入。
- 留痕重点：corpus 版本、覆盖场景和 intentional breaking changes。

## SEC-001：完成系统威胁模型

- Size：M
- Depends on：CON-001；可与 CON-002..005 并行
- 关联：D-005；PRD 10.3、13
- 目标：在选择加密方案前冻结资产、参与方、信任边界和攻击面。
- 交付：数据流图；资产清单；Relay/APNs/Provider/Host/Mobile 攻击者模型；STRIDE 或等价威胁表；风险 owner 和处置。
- 验收：覆盖配对、设备丢失、恶意 Relay、旧客户端、重放、跨会话审批、日志泄露和供应链；Critical/High/Medium 有明确控制或停止条件；安全 DRI 和独立评审者签字。
- 排除：直接选择密码算法或把 D-005 改为 Accepted。
- 留痕重点：风险编号、等级、接受者和复审时间。

## SEC-002：冻结信任根与设备生命周期 ADR

- Size：M
- Depends on：SEC-001
- 关联：D-005 接受门槛；PRD SP-05
- 目标：确定首设备加入、新设备授权、吊销、key epoch 和全部设备丢失行为。
- 交付：Accepted/Rejected ADR；配对状态机；设备授权证明；吊销传播目标；历史密文访问矩阵；无恢复 UX 要求。
- 验收：过期/消费/重放 QR 被拒绝；无可信设备时不能恢复 Relay 历史；吊销设备无法读取新 epoch 或发送新命令；双端确认与 comparison code 语义明确。
- 排除：Closed Beta 的恢复码和多用户组织身份。
- 留痕重点：备选信任模型、选择理由及用户可见代价。

## SEC-003：选择成熟安全协议并冻结 Security Envelope v0

- Size：M
- Depends on：CON-002、CON-003、SEC-002
- 关联：路线图 4.3；PRD SP-04、SP-07
- 目标：用经过审查的协议/库实现设备间认证加密、防重放和版本协商。
- 交付：协议选择 ADR；envelope schema；canonical encoding；签名覆盖范围；nonce/counter、expiry、key version 和 chunk 绑定规则；互操作向量。
- 验收：篡改 sender/recipient/session/turn/request/action/expiry 任一绑定字段均失败；旧 key epoch 和重放失败；未知安全版本 fail closed；独立密码学评审通过。
- 排除：自研 cipher、未评审的“临时加密”和密钥恢复。
- 留痕重点：库版本、审计状态、已知限制和轮换计划。

## SEC-004：定义远程审批规范化与 allowlist

- Size：M
- Depends on：CON-003、HC-009、SEC-001
- 关联：D-009；PRD 8、7.2
- 目标：定义哪些 OpenCode 请求能被确定性呈现和在手机允许一次。
- 交付：规范化算法；action hash 输入；风险级别规则；allow/deny/desktop-only 矩阵；Unicode/bidi/控制字符呈现规则；版本策略。
- 验收：shell 组合、解释器、重定向、命令替换、动态下载和未知影响范围均不能 allow；参数、cwd、executable、脚本内容或基准变化使决定失效；benign/ambiguous/dangerous corpus 全部得到预期分类。
- 排除：永久规则、网络访问、包安装、Git push 和任意 shell 的远程 allow。
- 留痕重点：每条 allow 规则的威胁依据、反例和 owner。

## SEC-005：发布安全测试向量与负面 corpus

- Size：M
- Depends on：SEC-003、SEC-004、CON-005
- 关联：Validation 6.1-6.2；PRD 发布门
- 目标：为 Host、Relay、Mobile 提供一致的安全回归输入。
- 交付：配对重放、旧 approval、跨会话替换、action mutation、过期、吊销、错误 key epoch、恶意 Unicode、超限 frame 和重复 request 向量。
- 验收：每个向量注明攻击目标、预期拒绝层和稳定错误码；三个消费端 CI 可运行；任何向量被接受时构建失败；向量本身不包含真实 Secret 或代码。
- 排除：渗透测试报告和生产红队。
- 留痕重点：新增攻击回归与关联威胁编号。
