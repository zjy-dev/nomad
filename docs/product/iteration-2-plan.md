# Nomad 下一迭代评估与路线图

| 字段 | 内容 |
| --- | --- |
| 文档状态 | Proposed 0.1 |
| 评估日期 | 2026-08-18 |
| 评估对象 | `feat/code-agent` Stage-1 Local Validation Slice |
| 建议迭代 | Controlled Pilot v0.2 |
| 规划周期 | 8 周，按阶段门推进 |
| 适用读者 | 产品、设计、架构、安全、Host、Relay、Mobile、QA |
| 关联文档 | [迭代 PRD](iteration-2-prd.md)、[需求池](product-backlog.md)、[Pilot 计分卡](pilot-scorecard.md)、[研究工具包](research-kit-v0.2.md) |

## 1. 结论先行

Stage 1 可以认定为一次成功的工程验证，但不能认定为 MVP、Internal Alpha 或产品价值验证。它证明了三件事：

1. Session Semantics v0 能被 Rust、Go、TypeScript 和 Python 参考实现共同消费。
2. Node Mobile、Go Relay、Rust Host 可以跨真实进程完成配对比对、状态投影、deny、Stop 和 `allow_once` 安全拒绝。
3. 在没有通过真实权限与安全门时，系统能够保持 fail closed，而不是为了演示开放远程批准。

它尚未证明四个更关键的问题：

1. 高频 CLI Agent 用户是否真的每周遇到值得付出安装成本的离桌阻塞。
2. 固定 OpenCode 版本的真实 Session 能否稳定投影为可用的手机体验。
3. 用户能否在没有开发者解释的情况下完成安装、配对、判断状态和处理阻塞。
4. 结构化手机控制是否比 SSH、tmux、远程终端或完成通知更有持续价值。

因此，下一轮的目标不是继续补齐完整 Private Alpha 功能，而是用可丢弃仓库和临时账户完成一次可由外部候选用户独立操作的真实 Controlled Pilot。产品 Discovery 与真实集成并行推进；只有问题门通过，才进入 Pilot 产品化开发。

## 2. 本轮产物评估

### 2.1 证据成熟度

采用五级证据等级：`0=无证据`、`1=文档假设`、`2=合成验证`、`3=内部真实验证`、`4=受控外部验证`、`5=真实长期使用`。

| 维度 | 等级 | 已有证据 | 主要缺口 |
| --- | ---: | --- | --- |
| 问题价值 | 1 | 战略、竞品和 JTBD 假设完整 | 没有 15 次访谈、8 人日记研究或真实替代成本 |
| Session 协议 | 3 | 9 条 golden trace、跨语言 conformance、真实进程闭环 | 没有固定 OpenCode 真实 Session 和长期兼容证据 |
| Host 集成 | 2 | fixture-backed adapter、真实 Rust 进程 | 不是 live OpenCode adapter；HC-009 对移动 allow 为 No-Go |
| Relay | 2 | opaque mailbox、ACK、TTL、容量和本地重启组件测试 | TEST-ONLY bridge；没有生产身份、E2EE、Push 和跨网恢复 |
| 移动体验 | 2 | 390×844 响应式页面、9 条 trace、状态和安全降级 | 首屏是 trace loader；Timeline 是协议事件；无真实安装、配对、Push、后台生命周期 |
| Reply / deny / Stop | 2 | mock 与真实进程命令往返、HostAccepted 分层 | 没有对真实 OpenCode Session 的用户操作 |
| Diff 审阅 | 1 | 参考 Changes UI | 有 diff 计数时仍回退到示例文件，不是权威 workspace diff |
| 安全 | 2 | 威胁模型、fail closed、`allow_once=false` | D-005 仍 Proposed；无 SEC-002/003、设备吊销、密钥轮换和独立评审 |
| 可靠性 | 2 | 合成故障注入、去重、gap 和 snapshot 测试 | 没有真实 Relay 重启闭环、100k 恢复、8 小时 workload 和用户网络数据 |
| 产品采用 | 0 | 无 | 没有无主持安装、激活、复用或留存数据 |
| Runtime 重写价值 | 1 | RT-001 预登记完成 | 没有 RT-005 测量和 RT-006 go/no-go |

### 2.2 体验走查结论

移动参考端在 390×844 视口下可稳定加载 9 条协议场景，状态不只依赖颜色，`HOST:ONLINE`、`CLIENT:LIVE`、`STATE:NEEDSPERMISSION`、Approval 禁用说明和底部导航均可识别。

但它的心智模型仍面向协议开发者，而不是目标用户：

- 用户进入后需要选择 golden trace，而不是看到自己的机器和待处理任务。
- Timeline 直接展示 `permission.requested`、`seq` 和 event ID，适合调试，不适合两分钟内做决定。
- Approval 只有 permission ID 和 action hash 占位，没有真实工具、参数、工作目录、影响范围和过期时间。
- Changes 显示的是示例文件，不能支持“我是否要回电脑继续处理”的判断。
- 没有真实安装、扫码配对、通知唤醒、前后台恢复和诊断体验。

下一轮 UI 不应围绕“把 reference 做得更漂亮”，而应围绕三个用户问题重新组织：首页是否需要我处理、发生了什么、我现在能安全做什么。

### 2.3 阶段判断

| 阶段门 | 当前判断 | 说明 |
| --- | --- | --- |
| Stage 1 工程闭环 | 通过 | synthetic/disposable 的真实进程闭环已验收 |
| Problem Discovery | 未开始 | 现有市场资料不能替代一手行为证据 |
| Controlled Pilot | 未通过 | 没有 live OpenCode、无主持安装和外部候选 |
| Security Architecture | 未通过 | D-005 Proposed，不能接触用户真实代码 |
| Internal Alpha | 不具备进入条件 | 真实仓库、安全、原生移动和可靠性门均未满足 |
| Native Runtime | 未决 | 只完成预登记，不能开始产品化 |

## 3. 下一迭代目标

### 3.1 目标声明

让 10 名符合筛选条件的外部候选用户，在项目提供的可丢弃仓库和临时 Provider 账户上，不依赖开发者现场解释，完成安装、配对、查看真实 OpenCode Session，并至少让一次 reply、deny 或 Stop 被 Host 接纳；同时获得是否值得进入 Internal Alpha 的一手证据。

### 3.2 成功标准

迭代只有同时满足以下条件才是产品意义上的成功：

- 完成至少 15 次有效情境访谈，8 人参加一周日记研究。
- H1 问题门通过：15 人中至少 8 人每周遇到一次离桌等待或状态不明，至少 5 人已有 workaround。
- 12 人任务原型测试中，关键任务完成率至少 85%，至少 70% 选择结构化页面为默认入口。
- 10 名 Pilot 候选中至少 8 人完成安装、配对和一次 Host 接纳操作。
- 至少 5 人愿意在一周内参加第二次无主持测试。
- 固定 OpenCode 版本至少稳定捕获 question、permission、Stop、diff 和 reconnect 五类真实事实。
- 一次 Relay 重启后，客户端能够恢复为 Live，没有重复 Host 接纳或无法解释的 gap。
- Pilot 期间保持 `allow_once=false`，不接触参与者真实仓库、个人 Provider 凭据或敏感代码。

### 3.3 非目标

- 不进入用户真实仓库。
- 不开放移动 `allow_once`。
- 不把 TEST-ONLY Relay 包装成生产 E2EE。
- 不实现 APNs、完整原生 iOS、Keychain、Face ID 或应用商店分发。
- 不扩展 Android、Windows、Linux、多 Host 或团队协作。
- 不实现自有 Runtime、Provider、工具链或完整 CLI/TUI。
- 不做付费、增长和品牌命名。

## 4. Opportunity Solution Tree

```text
Outcome：候选用户离开电脑后，能在两分钟内安全推进或止损一个真实任务
|
+-- O1：用户无法快速判断 Agent 现在是否需要自己
|   +-- S1：以“需要处理 / 运行中 / 最近完成”组织首页
|   +-- S2：把协议事件翻译成任务进展和最后活动时间
|
+-- O2：用户不知道远程操作是否真的到达并生效
|   +-- S3：区分 Relay received、Host accepted 和最终结果
|   +-- S4：Stale / Offline 时禁用命令并给出恢复动作
|
+-- O3：用户看不懂权限和改动是否安全
|   +-- S5：展示 Host 事实、真实工具输入和权威 diff
|   +-- S6：Pilot 只提供 deny / Stop，allow 保持关闭
|
+-- O4：安装、配对和故障恢复成本可能高于价值
    +-- S7：固定环境的一键检查、二维码比对和 doctor
    +-- S8：内容无关的漏斗、恢复和错误分型
```

## 5. 优先级原则

需求使用 RICE 进行相对排序，但以下硬门优先于分数：

1. 安全不变量与真实状态表达。
2. 能否形成 Pilot 的端到端用户闭环。
3. 能否产生下一步决策所需的证据。
4. 体验优化和扩展功能。

本轮资源顺序建议为：`Discovery / Research → live OpenCode 闭环 → onboarding 与真实任务 UI → 恢复与度量 → 安全架构设计 → Runtime 测量`。Runtime 测量可使用不超过 10% 的独立容量继续，不得阻塞 Controlled Pilot。

## 6. 里程碑与阶段门

### M0：范围与证据基线，2 个工作日

交付：

- 登记产品、技术、安全和研究 DRI。
- 冻结固定 OpenCode 版本、测试仓库、临时账户和 Pilot 数据边界。
- 发布筛选问卷、访谈脚本、日记模板和原型任务。
- 把 README、路线图、PRD 和需求池的当前阶段对齐。

退出条件：所有 P0 需求有 Owner、验收方法和证据路径；未决架构问题有 ADR Owner。

### M1：问题与交互门，第 1 至 3 周

产品/设计：完成访谈、日记研究启动和 12 人任务原型测试。

工程并行但不扩范围：完成 live OpenCode read-only capture、Relay restart E2E 和 SEC-002/003 设计草案。

阶段门：

- H1/H2 通过：继续 M2。
- H1 失败：停止 Pilot 产品化，重新选择目标用户或收缩为通知/Runtime 工具。
- H2 失败：保留协议资产，重新设计信息呈现；不开发远程审批。

### M2：Pilot-ready 真实闭环，第 4 至 6 周

交付：

- 固定 OpenCode 真实 Session 的投影与命令 adapter。
- 面向任务的 Home / Session / Action / Changes。
- 无主持安装检查、二维码比对、连接诊断和清理。
- reply、deny、Stop 的真实 Host 接纳与结果表达。
- 权威 diff、来源标识、Stale/Offline 安全降级。
- 内容无关的 Pilot 事件和错误分型。

退出条件：迭代 PRD 的 P0 场景全部通过；至少一次真实 Relay 重启恢复；项目成员使用测试仓库完成 20 次闭环且无重复 Host 接纳。

### M3：Controlled Pilot 与决策，第 7 至 8 周

交付：10 名候选用户的无主持试用、原始计分卡、问题分型、复测意愿和阶段决定。

决策：

| Pilot 结果 | 下一步 |
| --- | --- |
| 问题门和 Pilot 门均通过 | 进入 Security Architecture 收口和 Companion Internal Alpha |
| 问题成立但安装/理解失败 | 保留目标，下一轮只修 onboarding、信息架构和诊断 |
| 用户只需要通知 | 收缩为通知 + deep link，不继续完整 Companion |
| 用户坚持 raw terminal | 重新评估结构化控制面或转向安全远程终端辅助 |
| 问题频率不足 | 停止移动产品扩张，保留协议或 Runtime 技术资产 |

## 7. RACI

`A=最终负责`、`R=执行`、`C=必须咨询`、`I=知会`。人名在 M0 登记。

| 工作 | 产品 | 设计/研究 | 架构/技术 | 安全 | Host | Relay | Mobile | QA |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 问题与 Pilot 门 | A | R | C | C | I | I | I | C |
| Session / command contract | C | I | A | C | R | R | R | C |
| live OpenCode adapter | C | I | A | C | R | I | I | R |
| Pilot 数据边界 | C | I | C | A/R | C | C | C | C |
| 移动信息架构 | A | R | C | C | C | I | R | C |
| 恢复与可靠性 | I | I | A | C | R | R | R | R |
| Pilot 运营与分析 | A | R | C | C | I | I | I | C |
| 阶段 go/no-go | A | C | C | C/停止权 | I | I | I | C |

## 8. RAID Log

| ID | 类型 | 事项 | 概率/影响 | Owner | 缓解与触发动作 |
| --- | --- | --- | --- | --- | --- |
| R-01 | Risk | OpenCode 真实 pending permission 不能稳定保持 | 高/高 | Host | allow 保持关闭；view/deny/Stop 继续，记录 No-Go |
| R-02 | Risk | 用户只把产品当完成通知 | 中/高 | 产品 | Pilot 分别记录查看、reply、deny、Stop、diff；触发则收缩产品 |
| R-03 | Risk | Web reference 无法代表 iOS Push/后台体验 | 高/中 | Mobile | 本轮只验证交互与闭环；不得把结果外推到原生生命周期 |
| R-04 | Risk | 安装固定 OpenCode 和临时 Provider 成为主要摩擦 | 中/高 | 产品/Host | 提供预检和测试账户；单独记录产品摩擦与实验脚手架摩擦 |
| R-05 | Risk | 示例 diff 被误认成真实改动 | 已发生/高 | Mobile/Host | Pilot 前移除 fallback；没有权威数据就显示“暂无可审阅改动” |
| A-01 | Assumption | 目标用户愿意使用 iPhone 处理本机任务 | 未验证 | 产品 | Discovery 记录设备和实际离桌场景，不以兴趣代替行为 |
| A-02 | Assumption | deny/Stop/reply 足以验证初始价值 | 中 | 产品 | 访谈明确区分“有用但想要 allow”和“没有 allow 就无价值” |
| I-01 | Issue | 产品文档仍把仓库描述为尚无实现 | 已确认 | 产品 | 本轮同步 README 和路线图状态 |
| I-02 | Issue | 多份完成报告 Owner 为“未分配” | 已确认 | 技术 DRI | M0 将活跃需求重新分配到具体人 |
| D-01 | Dependency | SEC-002/003 被 Internal Alpha 和真实仓库使用阻塞依赖 | 高 | 安全 | Controlled Pilot 并行完成 ADR，未 Accepted 不进入真实仓库 |
| D-02 | Dependency | RT-005/006 决定 Runtime 是否继续 | 中 | 技术 | 与产品门独立；本轮不进入默认构建 |

## 9. 架构评审输入

架构团队需要把以下产品不变量视为约束，而不是实现建议：

- OpenCode 是 Validation Companion 的 Session owner；Connector 不能创建第二个领域 writer。
- Relay received、Host accepted、执行中和最终结果必须分开表达。
- Offline、Stale、版本不兼容或 action 变化时，远程命令 fail closed。
- 同一 request ID 最多由 Host 接纳一次；`OutcomeUnknown` 不自动重试。
- Permission 只有一套 upstream pending；Pilot 不开放 allow。
- Diff 必须来自当前 workspace 基线并标识外部修改；禁止示例数据回退。
- Push、日志和分析不包含 Prompt、源码、路径、命令或 diff。
- Web reference 只是 Controlled Pilot 的实验载体，不是原生移动安全和生命周期证据。

需要架构评审给出书面答案的问题：

1. 固定 OpenCode 版本的真实 adapter 边界和升级策略是什么？
2. Pilot 的 Host、Relay、Mobile 之间使用什么测试身份和内容保护，哪些能力明确不具备？
3. Relay 重启后 command、ACK、cursor 和 snapshot 如何收敛？
4. 权威 diff 在 Host 的基线、存储、切块和过期模型是什么？
5. Pilot 分析事件如何证明 Host 接纳和后续进展，同时不采集内容？
6. SEC-002/003 的信任根、加入、吊销、key epoch 和无恢复行为何时可评审？

## 10. 需求与交付治理

- 产品需求以 [需求池](product-backlog.md) 的 ID 为唯一索引。
- 每个进入开发的需求必须满足 Definition of Ready：用户结果、范围、验收、埋点、依赖、Owner 和证据路径齐全。
- 架构变化进入 ADR；产品范围变化进入 decision log；用户实验结果进入 Pilot 计分卡。
- 研发可把一个产品需求拆成多个技术任务，但不能在消费端私自新增协议语义。
- 完成代码不等于完成需求。只有验收用例、证据和用户状态均更新，需求才可标记 Done。
- 每周 Scope Review 只做四类决定：继续、拆分、降级、删除。新增需求必须说明替换掉哪项容量。
