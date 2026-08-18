# Controlled Pilot v0.2 PRD

| 字段 | 内容 |
| --- | --- |
| 状态 | Proposed 0.1 |
| 日期 | 2026-08-18 |
| 目标发布 | Controlled Product Pilot，不是 Internal Alpha |
| 产品目标 | 证明候选用户能在可丢弃真实任务中独立完成跨端推进或止损 |
| 用户范围 | 10 名外部候选，Apple Silicon macOS + iPhone 上的移动 Web 实验端 |
| 数据边界 | 项目提供的可丢弃仓库和临时 Provider 账户 |
| 安全边界 | 只开放查看、reply、deny、Stop；`allow_once=false` |
| 关联 | [评估与路线图](iteration-2-plan.md)、[需求池](product-backlog.md)、[计分卡](pilot-scorecard.md) |

## 1. 背景

Stage 1 已证明合成数据下的跨语言协议与真实进程闭环。当前界面、Host adapter 和 Relay 仍是 reference/test-only 实现：用户需要手动选择 trace，Host 不连接真实 OpenCode Session，Approval 缺少真实工具事实，Changes 回退到示例 diff，生产身份、E2EE、Push 和原生移动生命周期也未完成。

本轮用 iPhone 上的移动 Web 作为交互和真实闭环实验载体，不把结果外推为原生 iOS、Push、后台恢复或安全存储证据，也不改变 D-015 对正式 Validation Companion 首发平台的决定。

如果直接进入 Internal Alpha，团队会同时承担真实仓库安全、原生客户端、安装分发和产品价值四类未知风险。v0.2 用受控数据边界先回答价值与可用性问题，并为安全架构收口提供真实流程输入。

## 2. 用户与场景

### 2.1 目标用户

参与者必须同时满足：

- 每周使用 CLI code agent 至少三次。
- 最近两周至少三次任务运行超过十分钟。
- 能描述最近一次离开终端后的等待、回桌或远程处理事件。
- 使用 Apple Silicon Mac，并有可访问的手机。
- 接受只使用项目提供的临时仓库与账户。

以下用户不计入成功样本：项目成员、仅对概念感兴趣但没有真实长任务的人、只打开页面未完成 Host 接纳操作的人。

### 2.2 核心 Job Story

当我离开电脑而 Agent 仍在执行任务时，我想从手机快速知道它是否需要我，并在不打开完整远程终端的情况下安全地回复、拒绝或停止，以免任务因等待空转或继续跑偏。

### 2.3 核心任务

| ID | 场景 | 用户结果 | Pilot 操作 |
| --- | --- | --- | --- |
| T1 | Agent 正常运行 | 10 秒内判断任务仍在推进 | 查看状态和最后活动 |
| T2 | Agent 等待回答 | 看懂问题并让回复只提交一次 | reply |
| T3 | Agent 请求权限 | 看懂事实并安全终止不希望的操作 | deny 或 Stop |
| T4 | Agent 跑偏 | 停止当前 turn，结果状态可信 | Stop |
| T5 | 任务产生改动 | 判断改了哪些文件、是否值得回电脑 | 查看权威 diff |
| T6 | 网络或 Relay 中断 | 明确看到非 Live，并自动恢复到准确状态 | 无命令，观察恢复 |

## 3. 用户流程

```text
收到测试邀请
  -> 运行环境预检
  -> 安装固定 OpenCode + Pilot Connector
  -> 使用临时账户打开测试仓库
  -> 手机扫码并比对六位码
  -> 桌面启动预设任务
  -> 离开电脑
  -> 手机识别 Running / NeedsInput / NeedsPermission
  -> reply、deny 或 Stop
  -> 查看 Host accepted 与最终状态
  -> 查看真实 Changes
  -> 完成测试问卷；一周后选择是否无主持复测
```

任何一步失败都必须给出恢复动作或诊断编号。参与者不得被要求查看浏览器控制台、手工编辑数据库、开放公网端口或理解 event/seq/action hash。

## 4. 范围

### 4.1 Must：Pilot 阻断范围

#### 安装、配对与诊断

- 固定并校验 OpenCode 版本、macOS 架构、端口和测试仓库。
- Connector 只绑定 loopback，Host 主动连接测试 Relay。
- 手机扫描一次性二维码并在两端显示相同六位比对码。
- 配对码过期、已使用或不一致时拒绝，并提供重新生成入口。
- `doctor` 输出可复制的诊断 ID 和内容安全检查结果，不输出 Prompt、源码、路径、命令、diff 或凭据。
- Pilot 结束后可一键清理临时账户、本地状态和测试设备绑定。

#### 真实 OpenCode Session

- 只支持一个冻结版本。版本不符时阻止启动并给出安装命令。
- 从真实 Session 捕获 question、permission、tool、Stop、diff、连接中断和 turn 终态。
- 投影必须满足 Session Semantics v0；未知事件不得被展示为已理解的事实。
- Connector 不写 OpenCode Session 数据库，不创建第二套 pending permission。
- reply、deny、Stop 使用稳定 request ID；Relay 收到不能被显示为 Host 已执行。
- `allow_once` 在协议、Host 和 UI 三层均关闭；请求该命令返回 `ERR_SAFETY_BLOCKED`。

#### 移动任务控制面

- 进入产品后直接看到当前 Host 和 Session，不暴露 trace loader。
- 首页按“需要处理、运行中、最近完成”排序。
- 状态使用面向用户的文案，同时保留 Online/Offline 与 Live/Stale 的可解释区别。
- Session 页展示最近进展、最后活动、Agent 问题、工具摘要和结果，不默认展示协议事件名。
- Action 页展示 Host 已知事实；Pilot 只提供 reply、deny 和 Stop。
- 操作显示本地草稿、发送中、Relay 已收到、Host 已接受/拒绝和最终结果。
- Offline、Stale、版本不兼容或 snapshot digest 不一致时，禁用命令并说明如何恢复。
- Changes 只展示 Host 对当前 workspace 基线生成的权威 diff；无数据时显示空态，禁止示例回退。
- 外部编辑、二进制、超大文件和基线失效有显式标识。

#### 恢复和 Pilot 观测

- Relay 至少一次投递，客户端和 Host 按稳定 ID 去重。
- Relay 重启后，Host 与 Mobile 使用 cursor/snapshot 恢复；验证完成前不显示 Live。
- 恢复失败时保持 Stale，不允许 reply、deny 或 Stop。
- 采集内容无关的邀请、预检、配对、Session 可见、命令阶段、恢复结果和任务完成事件。
- 每次失败归类为“不需要、信息不足、不可信、不可靠、安装困难、实验脚手架”。

### 4.2 Should：有余量才进入 Pilot

- 任务完成摘要和测试结果摘要。
- Timeline 的“技术详情”折叠区，供诊断使用。
- 参与者可下载经过内容扫描的诊断包。
- 对第二次无主持测试提供一键重置场景。

### 4.3 Could：只设计，不实现

- 原生 iOS Push 与后台恢复 spike。
- SEC-002/SEC-003 的设备加入、吊销、key epoch 与 Security Envelope 原型。
- RT-005 基准执行。

### 4.4 Won't：本迭代明确不做

- 移动 allow once、任意 shell、永久权限规则。
- 用户真实仓库和个人 Provider Key。
- 生产 E2EE、APNs、Face ID、Keychain 和 App Store/TestFlight 发布。
- 自有 Runtime、云端续跑、远程创建任务。
- Android、多 Host、多人协作、团队策略和计费。

## 5. 功能需求与验收

需求的详细优先级、Owner 和依赖见需求池。以下是产品验收合同。

### FR-01：环境预检与版本门

验收：

- Given 不受支持的 OpenCode 版本，When 用户启动 Connector，Then 系统不建立 Pilot Session，并给出当前版本、要求版本和修复命令。
- Given 环境满足要求，When 用户完成预检，Then 结果可在 30 秒内完成且不要求公网入站端口。
- Given 预检失败，Then 记录失败阶段与错误码，不记录仓库路径和凭据。

### FR-02：一次性配对

验收：

- 两端比对码一致且均确认后才完成配对。
- 过期、重放、已消费或码不一致的请求全部拒绝。
- 10 名 Pilot 用户中至少 9 人无需人工帮助完成配对，P50 少于 30 秒。

### FR-03：真实 Session 投影

验收：

- 固定 OpenCode 版本的预设任务能产生可复现的 question、permission、Stop、diff 和 reconnect。
- 同一 durable event 不重复展示；发现 gap 时状态进入 Stale。
- 真实捕获有 provenance 标签，不与 synthetic fixture 混用为用户证据。

### FR-04：状态与任务时间线

验收：

- 90% 可用性测试用户能正确区分 Running、NeedsInput、NeedsPermission、Offline 和 Stale。
- 用户可以在 10 秒内回答“现在是否需要我”和“最后发生了什么”。
- 默认界面不要求用户理解 `seq`、digest、event ID 或内部任务编号。

### FR-05：reply

验收：

- 非空 reply 发送后显示 request 的完整阶段；只有 Host 明确返回后显示 Host accepted。
- 重复发送同一 request ID 一百次，OpenCode 最多接收一条用户消息。
- Stale/Offline 状态只保留本地草稿，不上传待执行命令。

### FR-06：deny 与 Stop

验收：

- deny 绑定同一真实 upstream pending；没有 pending 或已解决时返回 Stale/Rejected。
- Stop 只在 Online + Live 且存在活动 turn 时可提交。
- Relay ACK 不触发 Cancelled；只有 Host 观察到终态后更新 turn。
- `allow_once` 在 UI 不出现；构造请求也被 Host 拒绝。

### FR-07：权威 Changes

验收：

- 文件数、路径、增删统计和 hunk 来自 Host 当前基线。
- 没有权威 diff 时不展示示例内容。
- 外部修改和基线变化会使旧 diff 失效并明确提示。
- 用户能在 30 秒内回答“改了哪些文件”和“是否需要回电脑查看”。

### FR-08：恢复

验收：

- 在一次预登记 Relay 重启中，客户端在 30 秒内恢复为与 Host snapshot 一致的 Live。
- 同一命令不会被 Host 二次接纳，没有未解释的 durable event gap。
- 不能确认时保持 Stale 或 OutcomeUnknown，不自动重放命令。

### FR-09：Pilot 度量与隐私

验收：

- 可还原每名参与者从邀请到 Host 接纳的漏斗。
- 可分别报告 Relay received、Host accepted、最终结果和后续 durable progress。
- 自动扫描事件 payload，不允许出现 Prompt、源码、路径、命令、diff、Provider Key 或 session content。
- 支持删除某位参与者的 Pilot 数据并留下删除时间。

## 6. 非功能需求

| 维度 | Pilot 门槛 |
| --- | --- |
| 正确性 | 0 次跨 Session 操作、0 次同 request 二次 Host 接纳 |
| 恢复 | 预登记 Relay 重启 100% 收敛；失败即停止 Pilot |
| 性能 | 手机首屏本地状态 P95 1 秒内可见；远程新状态 P95 5 秒内可见 |
| 可用性 | 关键任务完成率至少 85%；配对成功率至少 90% |
| 隐私 | Relay、Push、日志、分析均不含 Session 内容 |
| 无障碍 | 状态不只靠颜色；按钮有可读标签；390×844 不横向溢出 |
| 兼容 | 仅冻结的 Apple Silicon macOS + OpenCode 版本；其他组合明确阻止 |

这些是 Pilot go/no-go 门，不是公开 SLA。

## 7. 数据与指标

### 7.1 关键事件

| 事件 | 触发 | 允许字段 |
| --- | --- | --- |
| `pilot.invite_accepted` | 接受测试 | participant_alias、cohort |
| `pilot.preflight_result` | 预检结束 | result、error_code、duration_bucket |
| `pilot.pair_result` | 配对结束 | result、error_code、duration_bucket |
| `pilot.session_visible` | 首次看到真实 Session | scenario、freshness |
| `pilot.command_stage` | 命令阶段变化 | action_type、request_alias、stage、error_code |
| `pilot.recovery_result` | 中断恢复结束 | fault_type、result、duration_bucket、gap |
| `pilot.task_result` | 任务完成 | task_id、result、duration_bucket、help_required |
| `pilot.retest_intent` | 选择是否复测 | yes/no、reason_code |

禁止字段：Session/turn 原始 ID、仓库和文件路径、用户文本、命令、diff、工具输出、Provider 标识和设备实名。

### 7.2 主指标

- Pilot 激活：完成配对、看到真实 Session，并至少一次 reply/deny/Stop 被 Host 接纳。
- 关键任务完成率：无需主持帮助完成 T1-T6 的任务数 / 分配任务数。
- 结构化 UI 偏好：对照测试后选择其作为默认入口的参与者比例。
- 再测试意愿：愿意一周内参加第二次无主持试用的人数。
- 恢复成功：预登记中断后 30 秒内与 Host snapshot 一致且无未知 gap。

完整记录格式见 [Pilot 计分卡](pilot-scorecard.md)。

## 8. Pilot 运行规则

- 第一批 3 人，修复阻断问题后再扩到 10 人。
- 研究员可观察但不得主动指导；用户明确求助后才记录一次 help。
- 任何跨 Session 操作、重复 Host 接纳、内容泄露或无法解释的 gap 立即暂停全部测试。
- 同一测试脚本、仓库 commit、OpenCode 版本和临时账户权限固定。
- 每次 Pilot 后在 24 小时内完成问题分型；产品文案问题与技术可靠性问题分开统计。
- 参与者可随时退出；退出后按约定删除测试数据和设备绑定。

## 9. 发布与回滚

进入 Pilot 前：

- 所有 Must 需求通过自动或手工验收。
- 已知产品 P0、安全 Critical/High/Medium 为 0。
- 安全 DRI 接受 Pilot Security Note，明确临时身份、TLS、设备解绑、测试 Relay 访问控制、数据保留和事故处置；该接受只适用于可丢弃测试数据，不等于 D-005 或生产 Security Envelope 通过。
- `allow_once=false` 有 UI、contract 和 Host 三层测试。
- 固定测试环境可从干净机器复现。
- 计分卡、同意说明、数据删除和事故联系人准备完成。

回滚触发：

- 任一安全停止条件。
- 两名连续用户无法完成相同步骤。
- 测试环境出现不可复现状态。
- 数据事件出现禁止字段。

回滚动作：停止新邀请、禁用测试 Relay、保留内容安全的证据、吊销临时账户、通知已受影响参与者并记录决策。

## 10. 待架构评审

| ID | 问题 | 最晚决定点 |
| --- | --- | --- |
| AR-01 | 真实 OpenCode adapter 使用 HTTP/SSE、进程桥还是组合边界 | M0 结束 |
| AR-02 | 测试身份和传输保护能否满足“可丢弃外部 Pilot”的数据边界 | M1 中点 |
| AR-03 | 权威 diff 的基线、chunk、缓存和失效模型 | M1 结束 |
| AR-04 | Relay 重启时 command 与 event 的恢复顺序和去重边界 | M1 结束 |
| AR-05 | Pilot 遥测如何关联一次操作而不上传真实 Session ID | M2 开发前 |
| AR-06 | SEC-002/003 是否能在 Pilot 期间形成 Accepted ADR | M3 决策前 |
