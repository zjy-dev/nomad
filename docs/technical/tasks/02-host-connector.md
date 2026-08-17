# Host Connector 任务

Host Connector 是 Validation Companion 的本机安全边界。所有任务必须遵守：OpenCode 是唯一 Session 领域 writer；OpenCode API 只在 loopback；Connector 不读取 Provider Key。

## HC-001：固定 OpenCode 基线与生成 adapter fixture

- Size：S
- Depends on：G0
- 关联：D-007；PRD HC-01
- 目标：把上游行为研究固定成可重复输入。
- 交付：精确版本/校验和；官方 API schema 快照；可丢弃仓库的 record/replay fixtures；许可说明。
- 验收：fixture 覆盖 Session、message、tool、permission、diff、abort 和 snapshot；CI 不访问实时上游也能重放；版本变化必须显式更新 manifest。
- 排除：支持多个 OpenCode 版本和修改上游源码。

## HC-002：完成 Connector 技术栈与本地存储 spike

- Size：M
- Depends on：CON-001、HC-001
- 目标：选择 Connector 实现语言、嵌入式存储和进程模型。
- 交付：候选原型；启动/RSS、SQLite durability、Keychain、签名分发和团队维护对比；ADR。
- 验收：至少比较 Rust 与团队可维护的替代方案；使用相同 fixture/durability；结论包含回滚和 migration；不以语言偏好代替数据。
- 排除：完整 Connector 功能和 Runtime Alpha 语言决定。

## HC-003：实现 OpenCode supervisor 与版本门

- Size：M
- Depends on：HC-001、HC-002
- 关联：HC-01、HC-03
- 目标：安全发现并连接仅绑定 loopback 的固定 OpenCode Server。
- 交付：discovery、health、认证、版本检查、状态和错误恢复接口。
- 验收：非 loopback 地址被拒绝；版本不符时所有可写远程操作关闭；重启后重新发现；错误能被 `doctor` 消费；外网扫描无法直接访问上游端口。
- 排除：自动升级 OpenCode 和 Provider 配置。

## HC-004：实现 OpenCode 到 durable event 的基础 adapter

- Size：M
- Depends on：CON-002、CON-005、HC-001、HC-003
- 关联：HC-02
- 目标：将上游事实稳定投影为 Session Semantics v0。
- 交付：Session/message/tool/turn 状态映射；上游去重键；Nomad seq 分配；未知事件 quarantine。
- 验收：固定 fixture 与 expected golden trace 一致；重复 SSE 不产生重复 durable event；未知上游事件不错误推进状态；不写 OpenCode DB。
- 排除：permission、diff 和跨网发送。

## HC-005：实现 Connector snapshot 与恢复投影

- Size：M
- Depends on：CON-004、HC-004
- 关联：SP-02
- 目标：在 Connector/OpenCode 重启后从上游快照恢复并与已有 Nomad seq 收敛。
- 交付：本地 projection store、upstream cursor mapping、snapshot/digest、reconcile 和 compaction 支持。
- 验收：cursor 与 event/outbox 原子提交；强杀后不丢已提交映射；上游快照差异产生可解释修正；100k 事件 fixture 达到内部预算。
- 排除：Mobile reducer 和 Relay retention。

## HC-006：实现有界加密 outbox 与 Relay sync client

- Size：M
- Depends on：CON-002、SEC-003、HC-005、RL-002 contract
- 关联：HC-07、SP-04
- 目标：可靠发送密文事件并在 Relay 故障时有界降级。
- 交付：outbox、frame/chunk、WSS reconnect、Relay ACK、backpressure、容量和 TTL 策略。
- 验收：事件提交与 outbox 原子；重复 ACK 安全；磁盘/容量超限产生明确诊断并可通过 snapshot 恢复；日志无正文；Relay ACK 不生成 Host command 状态。
- 排除：命令接纳和 Push。

## HC-007：实现 reply 的 Host 接纳去重

- Size：M
- Depends on：CON-003、HC-003、HC-005
- 关联：HC-04、MB-05
- 目标：把 Mobile reply 最多一次地接纳到固定 OpenCode Session。
- 交付：command journal、request validation、Host accepted/rejected、上游调用和结果投影。
- 验收：百万次同 request 重试只产生一次上游消息；Host offline/stale context/version mismatch 被拒绝；强杀窗口返回稳定已知结果或明确未知，不伪造完成。
- 排除：普通文本的离线服务端队列。

## HC-008：实现 Stop 与 interrupt-and-send 仲裁

- Size：M
- Depends on：CON-003、HC-007
- 关联：PRD 7.3
- 目标：确保旧 turn 确认停止后才提交新消息。
- 交付：Stop 去重、Stopping 投影、终态确认、deferred reply 状态机。
- 验收：重复 Stop 不重复发取消；未确认 Cancelled 时不提交新消息；旧、新 turn 不同时修改文件；断线或未知终态给出明确失败/未知状态。
- 排除：强杀任意本机进程和离线 Stop。

## HC-009：验证固定 OpenCode permission 阻断条件

- Size：M
- Depends on：HC-001、HC-003；可与 HC-004 并行
- 关联：D-007、路线图 4.1
- 目标：以 spike 证明 allow once 是否可安全进入产品。
- 交付：唯一 upstream pending ID、原始输入读取、pending 保持、桌面/手机竞争、断线和 action mutation 的可重复实验；书面 go/no-go。
- 验收：每个阻断条件都有 trace；任何失败结论必须自动关闭 allow once 的后续范围；结果由安全 DRI 复核。
- 排除：绕过上游权限系统或创建第二套 pending。

## HC-010：实现 permission projection 与 deny bridge

- Size：M
- Depends on：CON-003、HC-009、SEC-003
- 关联：PRD 7.2、MB-03
- 目标：无论 allow once 是否通过安全门，都提供 permission 查看、deny 和结果确认。
- 交付：permission projection、原始 Host 事实、deny request 去重、upstream resolve 和结果投影。
- 验收：deny 绑定同一 upstream pending；重复请求不产生第二个终态；已解决/过期/断线请求不可再次操作；若上游事实不足以安全绑定，则只展示并引导 Stop，不伪造 deny 成功。
- 排除：allow once、风险 allowlist 和第二套 pending。

## HC-011：实现 workspace baseline 与 diff projection

- Size：M
- Depends on：HC-002、CON-002
- 关联：HC-05、PRD 7.4
- 目标：生成带明确基准和归因限制的 workspace diff。
- 交付：Git/workspace baseline、文件统计、按文件 diff、rename/delete/untracked/binary/large-file 分类、外部修改标记。
- 验收：100 文件/1 万行 fixture 完整；基准变化使旧 diff 失效；外部修改不被描述成 Agent 产出；路径和 diff 只以密文离开 Host。
- 排除：手机直接编辑和严格进程级改动归因。

## HC-012：实现 Host 配对、设备密钥与吊销

- Size：M
- Depends on：SEC-002、SEC-003、RL-005、RL-006
- 关联：SP-05；PRD 7.1
- 目标：让 Host 安全完成双端配对并维护每设备身份。
- 交付：短期配对会话、comparison code、双端确认、Keychain 引用、device list/revoke 和 epoch 更新。
- 验收：两分钟过期、单次消费、不匹配失败；私钥不落普通文件；吊销在目标窗口内阻止新命令；全部设备丢失行为符合 ADR。
- 排除：密钥恢复和多账户组织。

## HC-013：实现 Connector CLI 与隐私安全诊断

- Size：M
- Depends on：HC-003、HC-006、HC-012
- 关联：PRD 5.2、HC-08
- 目标：提供 `connect`、`pair`、`devices`、`revoke`、`doctor`、`disconnect` 的稳定操作面。
- 交付：CLI contract、结构化错误码、版本/网络/存储/Push 检查、首次连接 Provider 数据边界告知、用户可预览诊断包。
- 验收：命令退出码和 JSON/人类输出稳定；首次连接明确说明 BYOK 不等于内容不离开本机、选入上下文的数据遵循 Provider 政策；诊断包扫描不含内容和 Secret；每项失败提供恢复动作；命令不复制 OpenCode Agent 创建/模型功能。
- 排除：完整 TUI 和 Provider 管理。

## HC-014：实现 Host 进程生命周期与 sleep 行为

- Size：M
- Depends on：HC-002、HC-003、HC-013
- 关联：HC-06；PRD 4.1、12
- 目标：让 Connector daemon 启停可控，并诚实表达自动睡眠、合盖和手动睡眠。
- 交付：daemon lifecycle、可选 sleep inhibition、合盖/手动睡眠状态和崩溃后恢复。
- 验收：退出/崩溃后恢复系统 sleep 设置；合盖/睡眠后 Mobile 不可安全操作；重复启停幂等；状态能被 Host 与 Mobile 诊断。
- 排除：承诺电脑休眠或关机后续跑。

## HC-015：实现 allow once 与 Host 最终复核

- Size：M
- Depends on：HC-009=GO、HC-010、SEC-003、SEC-004
- 关联：PRD 7.2、MB-03；D-009
- 目标：仅在 adapter 阻断验证通过时，实现 allow once 的 Host 端安全闭环。
- 交付：normalized facts、action hash、signed decision verify、当前 pending 重读、upstream atomic resolve 和结果确认。
- 验收：竞争只接受一个终态；任何参数/cwd/executable/script/baseline/version/expiry/revocation/freshness 变化均 fail closed；未知副作用不自动重跑；安全 corpus 全通过。
- 排除：永久规则、任意 shell、网络/包安装/Git push；HC-009 NO-GO 时任务取消而不是降标准。

## HC-016：构建 macOS 安装、升级、卸载与签名制品

- Size：M
- Depends on：HC-013、HC-014、OPS-002
- 关联：PRD 13；路线图阶段 2
- 目标：提供可验证来源、可升级、可回滚并可删除数据的 Apple Silicon macOS 制品。
- 交付：签名/notarized 制品、安装器、自动升级、上一版本回滚、卸载和可选数据删除。
- 验收：制品签名与 SBOM 可验证；升级保留兼容状态；不兼容 migration 安全停止；回滚演练通过；卸载能按用户选择清理 Connector 数据和密钥引用。
- 排除：Intel Mac、其他 Host OS 和公开商店分发。
