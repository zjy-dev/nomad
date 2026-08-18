# 产品决策记录

| 字段 | 内容 |
| --- | --- |
| 状态 | 持续更新 |
| 建立日期 | 2026-08-11 |
| 规则 | 重大方向变化需记录证据、负责人和影响，不覆盖旧决定 |

## 状态说明

- `Accepted`：当前规划按此执行，出现明确反证时重审。
- `Proposed`：方向倾向明确，仍需实验或技术评审。
- `Deferred`：当前不做，不等于永久拒绝。
- `Rejected`：已经评估，不进入当前产品方向。

## 决策总表

| ID | 决策 | 状态 | Owner | 证据 | 复审时间 |
| --- | --- | --- | --- | --- | --- |
| D-001 | 以 local-first 本机执行为默认 | Accepted | 产品 DRI | Strategy 4.1；Research 5 | Closed Beta 规划前 |
| D-002 | 产品对象是持久 Session，不是终端连接 | Accepted | 技术 DRI | Strategy 2、9.2；Mosh/tmux 调研 | Session Semantics v0 评审时 |
| D-003 | 手机是任务控制面，不是完整 IDE | Accepted | 产品 DRI | Strategy 4.3；Validation E2 | Discovery 结束 |
| D-004 | 跨端同步结构化事件，不默认镜像 PTY | Accepted | 技术 DRI | Research 4；Validation E2 | Session Semantics v0 评审时 |
| D-005 | 主路径采用出站 Relay + 应用层 E2EE | Proposed | 安全 DRI | Research 5；Validation H8 | Private Alpha 前，必须转为 Accepted 或停止外部发布 |
| D-006 | Rust 是默认候选，是否正式采用由基准决定 | Proposed | 技术 DRI | Research 6-7；Validation E5 | Native Runtime Spike 结束 |
| D-007 | 先发布 OpenCode Validation Companion，不做完整 fork | Accepted | 产品 DRI | Strategy 8.1；Research 3.1 | Private Alpha 结束 |
| D-008 | Validation Companion 沿用 OpenCode BYOK | Accepted | 产品 DRI | Strategy 11；PRD 11.1 | Closed Beta 规划前 |
| D-009 | 手机不创建 Session 或永久权限规则 | Accepted | 安全 DRI | PRD 8；Validation E2 | 独立安全评审后 |
| D-010 | 每个 Session 存储只有一个领域 writer | Accepted | 技术 DRI | OpenCode event store 调研；PRD 2 | Runtime Alpha 设计评审 |
| D-011 | MVP 不做云端续跑 | Accepted | 产品 DRI | Strategy 4.1；Research 5 | Closed Beta 结束 |
| D-012 | 核心 Runtime 和协议倾向开源 | Proposed | 产品 DRI | Strategy 4.6、11 | Closed Beta 前 |
| D-013 | 工作名使用 Nomad，正式名称待定 | Deferred | 产品 DRI | README 命名约束 | 首次公开发布前 |
| D-014 | Companion 与 Runtime Alpha 是两个独立阶段门 | Accepted | 产品 DRI | Roadmap 4.4、5、6 | Dual Spike 结束 |
| D-015 | Validation Companion 首发只支持 Apple Silicon macOS + iOS | Accepted | 产品 DRI | 4 人团队容量评审 | Discovery 结束，可因目标用户设备分布重审 |
| D-016 | 外部工具只保证 Host 接纳去重，不承诺副作用 exactly-once | Accepted | 技术 DRI | PRD 6-9；故障窗口分析 | Session Semantics v0 评审时 |
| D-017 | Stage 1 后先做 Controlled Pilot，不直接进入 Internal Alpha | Proposed | 产品 DRI | Stage-1 acceptance；Iteration 2 plan | M0 评审确认 |

这里的 Owner 是角色 DRI。Discovery 启动前必须在本表顶部补充具体姓名；未登记产品、技术和安全 DRI 时，路线图不进入执行状态。

## D-001：以 local-first 本机执行为默认

状态：`Accepted`

决定：仓库原件、Provider 凭据和工具执行默认留在用户自己的电脑。为完成推理，选定上下文会发送给用户选择的模型 Provider。Nomad Relay 不执行 Agent，也不持有会话内容密钥。

原因：

- 直接复用用户已有仓库、依赖和环境。
- 与 Cursor/Codex Cloud 等云 Agent 形成清楚边界。
- 为模型无关、自托管和企业数据边界提供基础。

代价：

- 电脑休眠、关机或断网时任务不能继续。
- Host daemon、诊断和跨平台发布成本由产品承担。

重审条件：超过一半的留存用户要求电脑关机后续跑，并愿意为云环境承担真实费用。

## D-002：产品对象是持久 Session

状态：`Accepted`

决定：Session 生命周期独立于 CLI、手机或 Web 的连接。Validation Companion 中 OpenCode 维护 Session，Connector 做协议投影，客户端显示和提交命令；Runtime Alpha 通过迁移门后可以成为新的 Session owner。

原因：断线恢复、多设备、Push、历史回放和远程审批都依赖稳定 Session ID、事件序号和状态机。tmux 的价值也说明连接不应拥有进程生命周期。

代价：Companion 必须实现 Connector、事件投影和快照校准；自有 Runtime 还要实现 SQLite、事件日志和版本迁移。两者都比单进程 TUI 更复杂。

重审条件：无。若不采用此模型，产品愿景本身不成立。

## D-003：手机是任务控制面

状态：`Accepted`

决定：首版手机只处理状态、回复、审批、diff、测试和 Stop，不做完整编辑器、Debugger 或 LSP UI。

原因：移动端最有价值的是两分钟内推进任务。GitHub Mobile、Claude/Codex Remote 等产品也采用短时高影响操作，而非桌面 IDE 缩小版。

重审条件：留存用户的任务记录显示，超过 30% 的失败远程流程都因无法做小范围代码编辑，并且不是可以通过补充指令解决。

## D-004：结构化事件优先于 PTY 镜像

状态：`Accepted`

决定：跨端协议传输消息、工具、权限、diff、测试和状态。Raw terminal 只作为后期高级 fallback。

原因：结构化事件可以安全渲染、按游标恢复、做幂等审批，并在手机上提供合适布局。PTY 控制序列、滚屏和输入模型都不适合作为核心协议。

重审条件：原型用户普遍无法通过结构化上下文完成任务，且默认 raw terminal 在可用性和安全测试中明显更好。

## D-005：出站 Relay + E2EE

状态：`Proposed`

决定：Host 只向 Relay 建立出站 WSS。内容在设备间应用层加密，Relay 只保存和转发密文，并触发通用 Push。该 E2EE 不覆盖用户所选模型 Provider 接收的推理请求。

替代方案：局域网直连、Tailscale-only、SSH/Mosh、P2P + Relay fallback、无 E2EE 云 tunnel。

选择原因：它最适合普通用户跨 NAT、切换网络、后台 Push 和多设备发现，同时减少平台读取代码内容的能力。

尚未接受的原因：信任根、设备加入、吊销轮换、Security Envelope v0、Web fallback、密文 retention、元数据和支持成本仍需 spike。Validation Companion 暂定不提供密钥恢复；全部可信设备丢失后不能恢复 Relay 历史。

接受门槛：

- 账户身份、两台设备配对、吊销和密钥轮换通过威胁模型。
- Relay 数据库泄露只暴露密文和已声明元数据。
- 自动故障注入达到 PRD 发布门，八小时和真实用户恢复分别报告原始次数。
- 用户理解“没有密钥恢复，全部设备丢失即失去 Relay 历史”的后果。
- Security Envelope v0 在上述信任与密钥模型确定后冻结，不提前固定签名和轮换字段。

## D-006：Rust 由基准决定

状态：`Proposed`

决定：Rust 是 Session/Event 内核的默认候选，不预先决定全量重写。

原因：类型系统、无 GC 内存控制、SQLite/Tokio/网络生态和跨平台单二进制与长 Session daemon 需求匹配。Codex 和 Goose 证明了可行性，但没有证明对本项目的收益。

接受门槛：

- 与固定基线的协议、事件和投影兼容 100%。
- Crash consistency 全部通过。
- 实验前冻结 3 至 5 个产品 workload、权重和非退化预算；至少一个用户关键 workload 提升 2 倍或峰值 RSS 下降 40%，其余关键 workload 不超预算。
- 团队具备 Rust 生产维护和故障处理能力。

拒绝后的方案：继续使用成熟 Runtime 或选择 Go，不为了宣传保留 Rust sidecar。

## D-007：OpenCode adapter 先验证需求

状态：`Accepted`

决定：Validation Companion 使用固定 OpenCode 版本的 HTTP/SSE 接口进入 Private Alpha。长期产品不做完整 OpenCode fork，也不承诺配置、数据库和插件兼容。自有 Runtime 通过独立阶段门后，只在 canary cohort 中迁移。

原因：OpenCode 已有 Session、diff、permission 和多客户端能力，可以把数月 Runtime 开发从需求验证的关键路径移开。上游内部架构仍在迁移，完整 fork 会产生持续合并成本。

约束：

- 在界面和文档中清楚说明 adapter 原型与自有 Runtime 的区别。
- 固定版本，Adapter 转换到内部协议，不把上游私有事件直接暴露给手机。
- Dual Spike 必须证明 OpenCode permission 可由 Connector 绑定同一 upstream pending request、手机/桌面原子竞争并在断线时 fail closed。验证失败时移动端只能查看、拒绝和 Stop，不能允许。
- 遵守 MIT 许可和 OpenCode 对衍生名称的非关联说明。

## D-008：MVP 使用 BYOK

状态：`Accepted`

决定：用户在 OpenCode 中配置 Provider Key 并承担 Token 成本。Nomad Connector 不读取或保存 Provider Key，不代理推理、不销售 Token 套餐。

原因：降低资金、滥用、税务和 Provider 合规复杂度；保持模型无关；让团队专注跨端闭环。

重审条件：BYOK 成为激活漏斗最大障碍，或企业客户明确要求统一模型网关。

## D-009：手机不创建永久全局权限规则

状态：`Accepted`

决定：手机只能对远程 allowlist 中的结构化操作允许一次、拒绝或 Stop，不能创建 Session 或永久规则。任意 shell、高风险操作和规则配置回到本机处理。

原因：小屏、远程和 Push 场景更容易误触，永久 wildcard 的影响很难在卡片中完整呈现。

重审条件：安全评审通过、用户能准确理解规则范围，且重复低风险审批成为主要任务阻塞。

## D-010：Runtime 唯一写 Session 数据

状态：`Accepted`

决定：每个 Session 数据库只有一个领域 writer。Validation Companion 中 OpenCode 是 Session writer，Connector 只保存传输游标和设备状态；Runtime Alpha 接管后由 Runtime 独占写入，不能让 Bun、Rust 或多个客户端长期同时写同一个 SQLite 文件。

原因：Event sequence、projector、permission 和 turn ownership 需要同一原子边界。WAL 和 busy timeout 不能解决领域状态竞争。

重审条件：无。可以替换 Runtime 实现，但不能放弃单一 writer 原则。

## D-011：MVP 不做云端续跑

状态：`Accepted`

决定：Host 睡眠或关机时明确显示 Offline，不自动把任务迁到云端。

原因：云 runner 会引入环境复制、Secret、计费、合规和 Git 交付，是另一套产品。它会拖延当前核心问题验证。

补充：活跃任务可以由用户选择阻止系统自动睡眠。合盖、手动睡眠、关机和断电仍会离线，并在 UI 中提前说明。

重审条件：完成 Closed Beta，local-first 留存成立，并有单独团队或资源验证云 runner。

## D-012：核心 Runtime 和协议倾向开源

状态：`Proposed`

决定倾向：CLI、Runtime、Session Protocol 和自托管所需组件开放源码；托管 Relay、Push 运维和企业控制面可作为商业服务。

原因：目标用户关心代码、权限和自托管。开放核心也有利于 Agent adapter 和协议生态。

待决：Apache-2.0、MIT 或其他许可；是否开放完整 Relay；Contributor 和商标政策。

最晚决定点：Closed Beta 前。更晚会造成外部贡献、依赖和商业预期混乱。

## D-013：Nomad 只是工作名

状态：`Deferred`

决定：内部文档暂用 Nomad，未做商标、域名、包名和应用商店检索前不对外发布。

命名要求：

- 不包含 `opencode`，避免关联和商标混淆。
- CLI 命令短、易拼写、搜索结果可区分。
- iOS、Android、npm、Homebrew、Cargo 和主要域名有合理可用性。
- 中文和英文语境没有明显负面含义。

## D-014：Companion 与 Runtime Alpha 分开

状态：`Accepted`

决定：最先进入外部测试的是固定 OpenCode 版本的 Validation Companion。自有 Runtime 只有在 Native Runtime Spike 通过后才启动，并且不能阻塞 Companion 的产品验证。

原因：跨端需求与原生重写收益是两个不同假设。把它们绑成一个 MVP 会让 Runtime 开发推迟用户验证，也会在技术门失败时失去可发布路径。

重审条件：无。后续可以迁移底层实现，但产品和技术阶段门仍分别记录。

## D-015：首发单平台

状态：`Accepted`

决定：Validation Companion 只支持 Apple Silicon macOS Host 和 iOS Mobile。Closed Beta 前根据真实用户设备与流失数据选择第二个平台维度。

原因：一名 Mobile 工程师无法在八周内同时保证 iOS、Android、大 diff、Push、后台、密钥和无障碍；Host 端也不能同时覆盖四个架构而不挤压安全测试。

重审条件：Discovery 显示首要用户明显集中在其他组合。此时替换首发组合，不增加并行组合。

## D-016：不承诺外部副作用 exactly-once

状态：`Accepted`

决定：同一 request ID 最多被 Host 接纳并启动一次。在外部副作用已经成功、但本地结果尚未持久化时崩溃，Turn 进入 `OutcomeUnknown`，系统不自动重跑。

原因：Git push、HTTP 请求、包安装和任意程序不能参与 Runtime 的本地事务。网络层至少一次传递不可能给这些外部系统提供通用 exactly-once 保证。

重审条件：某个结构化工具提供专用幂等键和 reconciliation 时，可以单独增强该工具的保证，不能扩写成全局承诺。

## D-017：Stage 1 后先做 Controlled Pilot

状态：`Proposed`

建议决定：Stage-1 synthetic/disposable 工程闭环通过后，下一迭代先完成 Problem Discovery 与 Controlled Product Pilot，不直接进入 Companion Internal Alpha。Pilot 只使用项目提供的可丢弃仓库和临时账户，只开放查看、reply、deny 和 Stop，保持 `allow_once=false`。

原因：Stage 1 证明了协议和真实进程可工作，但尚无问题频率、无主持安装、真实 OpenCode Session 或外部用户价值证据。直接进入 Internal Alpha 会同时扩大产品、安全、原生移动和真实仓库四类风险。

转为 Accepted 的条件：M0 评审登记产品、技术和安全 DRI，并共同确认范围、数据边界和资源。

重审条件：Problem Discovery 和 Controlled Pilot 结束。若产品门通过，进入安全架构收口和 Internal Alpha；若只需要通知、结构化 UI 不成立或问题频率不足，则收缩、转向或停止。

## 待进入决策记录的问题

以下事项还没有足够证据，不应在实现中悄悄冻结：

- 移动技术栈。
- Closed Beta 后的密钥恢复模型。
- Session 内修改文件的默认权限。
- Community 版自托管 Relay 的范围。
- 正式开源许可和商标政策。
- Runtime 最终是独立单进程、sidecar 还是统一二进制。
- 何时支持 Windows、ACP adapter 和远程发起任务。
