# 市场与技术调研

| 字段 | 内容 |
| --- | --- |
| 调研日期 | 2026-08-10 |
| 资料优先级 | 官方文档、官方仓库、官方发布记录优先 |
| 用途 | 支撑产品定位和技术边界，不替代一手用户研究 |

## 1. 结论

CLI code agent 已经是成熟品类，竞争从“能否修改代码”转向四个方向：本机交互、云端异步任务、跨端远控和团队治理。Claude Code、Codex、Cursor、OpenCode、Gemini CLI 等产品已经覆盖大量基础能力，重新实现一套普通 CLI 的机会有限。

移动端需求也不是空白。Claude Code Remote Control、Codex Remote、Cursor Mobile 和 Happy 是明确的供给侧信号，也提供了可研究的交互与技术先例。它们不能证明使用频率、留存、支付意愿或 E2EE 是否驱动选择，这些问题仍需 Nomad 的一手研究。可见的产品空档是：模型无关、local-first、开放协议、自托管、E2EE 和移动原生控制同时成立。

技术上，OpenCode 已经采用“Server + 多客户端”的结构，并公开 HTTP/OpenAPI/SSE 接口。这适合快速验证 companion，但其局域网/自建服务能力不等于完整的互联网移动连接产品。直接暴露 `opencode serve` 无法替代设备身份、出站中继、Push、应用层加密、幂等审批和断线恢复。

用 Rust 重写可能改善冷启动、内存、事件持久化和长时间 daemon 稳定性，但 Agent 的主要墙钟时间仍在模型、网络、shell 和测试。重写价值必须通过固定 workload 证明。

## 2. 产品类型

| 类型 | 代表产品 | 运行位置 | 移动/远程形态 | 对 Nomad 的意义 |
| --- | --- | --- | --- | --- |
| 本机 CLI Agent | OpenCode、Aider、Gemini CLI、Goose | 用户电脑 | 多为终端、本地 Web 或自建连接 | 功能基础成熟，不应逐项复制 |
| 单厂商本机远控 | Claude Code Remote Control、Codex Remote | 用户电脑 | 官方 Web/手机控制本地任务 | 提供核心 Job 的供给侧信号，也抬高体验门槛 |
| 云端异步 Agent | Cursor Cloud Agents、Codex Cloud、GitHub Copilot | 托管沙箱/Runner | Web/手机查看、跟进和审阅 | 解决电脑离线，但隐私和环境模型不同 |
| 跨 Agent 移动 Companion | Happy | 用户电脑 + Relay | iOS、Android、Web、Push、E2EE | 最接近产品假设，说明不能只靠“有手机端”差异化 |
| 远程终端 | Termius、Mosh、tmux、Tailscale | 用户电脑/服务器 | TTY、VPN、重连 | 是成熟 fallback，但不理解 Session 语义 |

## 3. 竞品摘要

以下只记录对当前规划有直接影响的能力。商业产品内部实现不可见时，不对加密或协议作无依据推断。所有“未找到”均指截至调研日期在官网文档、官方仓库和官方 release notes 中未找到，不表示产品一定没有该能力。事实后的来源编号对应第 10 节，访问日期均为 2026-08-10。

### 3.1 OpenCode

已确认事实：

- 官方仓库 `anomalyco/opencode` 使用 MIT License，当前主体为 TypeScript/Bun。[R1][R2]
- 默认 CLI 是 TUI，也支持 `run` 非交互命令和 JSON 事件输出。[R4]
- 支持 Session continue、resume、fork、abort、export/import。[R4]
- `serve` 提供 OpenAPI 3.1、HTTP API 和 SSE；Session、message、diff、permission、file 等都有结构化接口。[R3][R7]
- `web` 提供浏览器界面；TUI 可以 `attach` 到已有 Server，多客户端共享 Session 和状态。[R3][R5]
- 网络访问默认绑定 `127.0.0.1`。可绑定 `0.0.0.0`、使用 mDNS，并通过环境变量设置 HTTP Basic Auth。[R3][R5]
- `acp` 使用 stdin/stdout 上的 NDJSON，不是移动端 WAN transport。[R6]

产品判断：

- 它是需求原型和协议研究的最佳现成基础。
- 它已有多客户端架构，因此 Nomad 不能把“Server + 手机”本身当作长期壁垒。
- Basic Auth、自行开放端口和本地 SSE 不解决跨网发现、Push、设备吊销、E2EE 和幂等恢复。
- OpenCode 本身正在从 legacy core 迁移到新的 schema/protocol/core/server，直接追逐内部实现会产生高维护成本。

### 3.2 Claude Code

已确认事实：

- 官方 Remote Control 支持从 Claude Web 和移动端连接本地 CLI Session。[R8]
- 官方 Changelog 和发布记录覆盖移动/Web 客户端、权限请求、Workspace diff、Push、断线重连和后台 Agent 状态。[R9]
- Remote Control 与 Anthropic 的账户、API 和产品体系结合；自定义 Base URL 或其他运行模式存在限制。[R8][R9]

产品判断：

- 第一方 Remote 已经把“离桌审批”从差异化功能变成品类基线。
- Nomad 若只包装 Anthropic，不会比第一方体验更有优势。
- 模型无关、自托管和可审计才是可争取的人群，但需要实际迁移意愿证据。

### 3.3 OpenAI Codex

已确认事实：

- Codex CLI 为 Rust 实现并采用 Apache-2.0 License。[R10]
- CLI 支持交互、非交互、Session resume/fork 和结构化事件。[R10]
- Codex Remote 允许在手机上控制连接电脑中的任务；Codex Cloud 则在隔离云环境执行。[R11]
- 移动体验覆盖任务创建、引导、审批、文件/diff 和测试结果。[R11]

产品判断：

- 它证明 Rust 足以承载完整 CLI Agent，但不能由此推导 Nomad 必然更快。
- “本机 Remote + Cloud Agent”双路径是长期产品参照，Nomad 初期只做本机路径。

### 3.4 Gemini CLI、Aider、Goose

已确认事实：

- Gemini CLI 提供开源 CLI、非交互输出、Session 管理、MCP、ACP、Skills、Hooks 和 Subagents；本轮未找到第一方移动远控闭环。[R28]
- Aider 是成熟的 Python CLI pair programmer，强调 Git、BYOK、lint/test 和多模型；本轮未找到结构化多客户端远控作为主要产品。[R29]
- Goose 使用 Rust，支持 CLI、Desktop、API、MCP 和多 Provider；本轮未找到与 Claude/Codex 类似的第一方手机远控。[R30]

产品判断：

- 开放模型用户仍有移动 companion 空档。
- 这些产品的扩展广度提醒团队：首版自有 Runtime 不可能通过功能数量竞争。

### 3.5 Cursor、GitHub Copilot

已确认事实：

- Cursor Cloud Agents 运行在隔离远程环境，支持 Web/移动端跟进；官方提供 iOS/iPadOS 客户端和 Android PWA。
- GitHub Copilot coding agent 在 GitHub Actions 环境中工作，以分支和 Pull Request 交付，GitHub Mobile 适合通知和代码审阅。

产品判断：

- 移动端应该围绕任务、diff、结果和决策，而不是复制桌面 IDE。
- Cloud Agent 解决的是另一类 Job：电脑关机仍运行。Nomad 需要明确 Host 离线状态，不能制造同等承诺。

### 3.6 Happy

已确认事实：

- Happy 是开源 iOS、Android 和 Web companion，通过本地 wrapper/daemon 驱动 Claude Code、Codex 等 Agent。
- 官方仓库描述了二维码配对、跨端同步、Push、权限处理和 E2EE。
- 协议将持久更新与瞬时事件分开，并维护序号用于同步。
- Voice 能力会扩大第三方数据边界，不等同于核心 E2EE 路径。

产品判断：

- Happy 是最直接的供给侧信号和架构先例，也是最需要正视的竞品。它的存在本身不证明留存或支付意愿。
- Nomad 不能用“E2EE + 手机远控”作为唯一定位，必须在自有 Runtime、模型开放性、可靠性、安全审批或自托管上做到明显更好。
- MVP 语音只做可编辑文本草稿，不让第三方 Voice Agent 读取完整 Session 或批准工具。

## 4. 移动交互研究

### 4.1 成熟模式

| 环节 | 已被验证的模式 | Nomad 采用方式 |
| --- | --- | --- |
| 配对 | Happy 已实现二维码和设备确认；是否优于手输地址仍由 E3 测试 | 短期 QR + 双端相同码 + 每设备密钥 |
| 发现 | 账户下列出机器和 Session，主机只连出 | 托管或自建 Relay 目录，不开公网端口 |
| 弱网 | Mosh 同步最新屏幕，业务 App 使用 cursor/snapshot 恢复 | 持久事件 seq + 快照校验，UI 显示 Stale |
| 后台 | tmux/daemon 让任务生命周期独立于客户端 | Runtime 是 Session owner，手机后台只靠 Push |
| 审批 | 结构化 request-response 优于聊天中的“可以吗” | 本机生成事实和 hash，手机签名决定 |
| Diff | GitHub Mobile 按文件审阅，先摘要再加载内容 | 文件统计、统一 diff、超大文件懒加载 |
| 语音 | 移动终端常先转成可编辑文本 | 只生成草稿，不直接执行或审批 |

### 4.2 不采用的默认模式

- ANSI/PTY 字节镜像。它无法可靠表达权限、diff 和最终状态，也容易受到控制序列影响。
- 锁屏上的允许按钮。锁屏内容和误触风险都不可接受。
- 离线审批队列。过期决定可能在网络恢复后执行到不同上下文。
- 手机端永久 `approve all`。长期规则应在桌面建立并明确匹配范围。
- 对完整 Session 有访问权的第三方语音 Agent。它扩大隐私边界，却不是首版核心价值。

## 5. 连接架构比较

| 方案 | 优点 | 主要问题 | 结论 |
| --- | --- | --- | --- |
| 局域网直连 | 延迟低、无云 | 不跨网，TLS 和 Push 困难，端口暴露 | 仅开发模式 |
| Tailscale 直连 | WireGuard、NAT 穿透、Relay 看不到明文 | 要安装 VPN，企业和移动 onboarding 较重 | 自托管/高级模式 |
| SSH + tmux | 成熟、进程持续、通用 | 弱网和移动交互差，不理解 Agent 语义 | 应急 fallback |
| Mosh + tmux | IP 漫游和丢包恢复好 | 需要 UDP，只同步终端屏幕 | 高级 terminal 模式 |
| Cloud tunnel | 出站连接，发现和账户简单 | 若无应用层加密，平台可见内容 | 只作为传输基础 |
| Cloud Relay + E2EE | 跨网、Push、结构化协议和内容隐私兼顾 | 密钥恢复、元数据和短期存储复杂 | MVP 首选 |
| P2P + Relay fallback | 可降 Relay 带宽和延迟 | ICE、TURN、移动后台和企业网络复杂 | 规模后评估 |
| 云端执行 | 电脑关机仍运行 | 环境、凭据、合规和成本完全不同 | 后续独立产品线 |

建议架构：

```text
CLI/TUI ───────────────┐
Local API ─────────────┤
                       v
                 Local Runtime
          Session / Tools / Providers
            SQLite durable events
                       |
                 outbound WSS
                       |
             Relay: ciphertext only
              routing / push / ack
                       |
                Mobile Companion
```

Relay 仍能看到账户、设备和 Session 的不透明 ID、时间、IP、消息大小和在线状态。产品不能把 E2EE 描述成“没有任何元数据”。

## 6. OpenCode 重写边界

### 6.1 官方基线

本轮源码研究固定在 OpenCode `v1.18.16` 对应源码树。该版本的结构显示：

- 正式入口仍在 `packages/opencode`，同时存在新的 `packages/core`、`schema`、`protocol`、`server`、`llm`、`tui` 和 `cli`。
- 新 API 标注为 Experimental，内部迁移尚未完全结束。
- Provider、Tool、Plugin、MCP、LSP、TUI 和 Server 的生态面很大。
- SQLite durable event 不只是 append log；Event、sequence 和 projector 在同一事务中提交。
- 流式 delta 与可回放的 durable ended event 是不同语义。
- 文件搜索、SQLite、watcher、PTY、tree-sitter 等热点已经部分使用原生库或外部程序。

### 6.2 推荐的最小原生内核

若以兼容原型开始，首个 Rust spike 只负责：

- Session list/get。
- Message/context/history 分页读取。
- Durable event append、aggregate sequence 和版本检查。
- Event 与 Session/message projection 同事务提交。
- Snapshot、cursor、历史重放和 durable SSE。
- 指标：事务耗时、DB busy、subscriber lag、恢复耗时。

首版不重写：

- 75+ Provider 和 OAuth/云凭据链。
- JavaScript 插件、Custom Tool、Zod 和 Hooks。
- MCP、LSP、ACP 的完整 lifecycle。
- TUI、Web、Desktop、PTY 和 IDE 集成。
- 全部 OpenCode HTTP API、旧数据迁移和配置兼容。

产品最终若选择自有 Runtime，可以逐步实现 Provider 和核心工具，但不能把兼容 spike 的窄边界误认为完整 Agent 已经完成。

### 6.3 语言比较

| 维度 | Rust | Go | Zig |
| --- | --- | --- | --- |
| 事件状态机和类型表达 | 强 | 足够，Tagged union 较弱 | 强但需更多自建 |
| HTTP/SSE/WebSocket 生态 | 成熟 | 非常成熟 | 相对不足 |
| 长 Session 内存控制 | 强，无 GC | GC 需基准验证 | 强，手工管理风险高 |
| SQLite 与事务控制 | 成熟 | 成熟但需处理 cgo/纯 Go 取舍 | 可行，生态较薄 |
| 跨平台单二进制 | 成熟 | 最简单 | 强 |
| 团队迭代速度 | 学习成本较高 | 通常更快 | 风险最高 |
| 当前建议 | 默认候选 | 团队 Go 能力明显更强时采用 | 只用于经 profiling 证明的窄热点 |

语言决定不能独立于团队。没有 Rust 生产经验和 on-call 能力时，Go 可能是更好的产品选择。

## 7. 性能事实与假设

有源码或发布记录支持的事实：

- OpenCode 曾通过 lazy loading 报告 CLI 启动改善，说明模块加载是实际热点之一。
- 长 Session 内存、事件批量传播、bash parser 内存和大型 Git snapshot 都出现过明确优化或文档提示。
- 官方建议 `run --attach` 复用 Server，避免每次 MCP 冷启动。
- Grep/Glob 使用 ripgrep，单纯改写 TypeScript wrapper 不会获得同等数量级收益。

仍需测量的假设：

- SQLite/JSON 投影在十万事件 Session 中占显著 CPU 和内存。
- 同步 SQLite 与单连接串行会造成可见的尾延迟。
- Rust 能降低完整 Session 恢复的峰值 RSS。
- Native fanout 能在多客户端和高 delta 速率下减少延迟。

不应宣称：

- Rust 会降低 Provider TTFT 或模型生成时间。
- Rust 会加快 `npm install`、编译、测试和 Docker build。
- 原生语言会自动改善 Agent 任务质量。
- 微基准的 JSON 性能可以代表完整 Agent 工作流。

## 8. 市场与商业判断

目前不使用未经核验的宏观 TAM 数字。这个品类仍在高速变化，公开“AI coding market”报告通常把 IDE、补全、平台和 Agent 混在一起，对当前决策帮助有限。

早期用 bottom-up 方式验证：

```text
合格 CLI Agent 用户
× 跨端激活率
× 第 4/8 周留存
× 托管连接付费转化
× 每用户月价格
- Relay、Push、支持和退款成本
```

竞品价格的绝对值会快速变化。对 Nomad 更重要的是用户当前已经为模型订阅、API Token、远程终端或云 Agent 支付多少，以及托管连接是否能成为独立价值。建议在 Closed Beta 用真实支付测试 12 至 20 美元个人价格，而不是在规划阶段定价。

## 9. 对产品规划的直接影响

| 调研发现 | 规划决定 |
| --- | --- |
| 第一方手机 Remote 已存在 | 不用“有移动端”作为唯一定位 |
| Happy 已提供跨 Agent + E2EE 的产品先例 | 必须在 Runtime、可靠性、安全或自托管上继续拉开差异，并自行验证需求 |
| OpenCode 已有 Server/OpenAPI/SSE | 用它快速验证，不先全量重写 |
| 手机成功产品聚焦短时高影响操作 | MVP 只做状态、回复、审批、diff、Stop |
| TTY 远控成熟但不适合结构化决策 | Raw terminal 仅作后期 fallback |
| 断线问题集中在 Session 和权限状态 | 事件协议、幂等和快照先于 UI 丰富度 |
| 高性能语言不影响模型主延迟 | Rust 采用条件是本地基准过线 |
| E2EE 与服务端搜索/恢复有取舍 | 首版减少 Web、分享和无条件恢复承诺 |

## 10. 主要来源

页面内容和版本可能在调研后变化。实现时应固定版本并重新核对。

### OpenCode

- [R1] 官方仓库与 MIT License：https://github.com/anomalyco/opencode
- [R2] `v1.18.16` Release：https://github.com/anomalyco/opencode/releases/tag/v1.18.16
- [R3] Server/OpenAPI/SSE：https://opencode.ai/docs/server/
- [R4] CLI、run、attach 和 Session：https://opencode.ai/docs/cli/
- [R5] Web、多客户端和网络访问：https://opencode.ai/docs/web/
- [R6] ACP：https://opencode.ai/docs/acp/
- [R7] 固定源码 commit 与 OpenAPI：https://github.com/anomalyco/opencode/tree/d90532a5952c08c4376167294ef7c316b8817f72

### 移动与远程 Agent

- [R8] Claude Code Remote Control：https://code.claude.com/docs/en/remote-control
- [R9] Claude Code Changelog：https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md
- [R10] OpenAI Codex CLI：https://github.com/openai/codex
- [R11] OpenAI Codex Remote：https://developers.openai.com/codex/remote/
- [R12] Cursor Mobile/Cloud Agents：https://cursor.com/docs/cloud-agent
- [R13] Happy 官方仓库：https://github.com/slopus/happy
- [R14] Happy 加密设计：https://github.com/slopus/happy/blob/2c8ecacc19f14abd81111a4605ac8c7f6bedb7e1/docs/encryption.md
- [R15] Happy Protocol：https://github.com/slopus/happy/blob/2c8ecacc19f14abd81111a4605ac8c7f6bedb7e1/docs/protocol.md
- [R16] Happy Privacy：https://github.com/slopus/happy/blob/2c8ecacc19f14abd81111a4605ac8c7f6bedb7e1/PRIVACY.md
- [R17] GitHub Mobile：https://docs.github.com/en/get-started/using-github/github-mobile
- [R18] GitHub Pull Request Review：https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/reviewing-proposed-changes-in-a-pull-request

### 远程连接与恢复

- [R19] Mosh 与技术论文：https://mosh.org/ 、https://mosh.org/mosh-paper.pdf
- [R20] tmux Session 模型：https://github.com/tmux/tmux/wiki/Getting-Started
- [R21] Tailscale 架构：https://tailscale.com/kb/1151/what-is-tailscale
- [R22] Tailscale DERP：https://tailscale.com/kb/1232/derp-servers
- [R23] Tailscale Tailnet Lock：https://tailscale.com/kb/1226/tailnet-lock
- [R24] VS Code Remote Tunnels：https://code.visualstudio.com/docs/remote/tunnels
- [R25] SSE 重连与 Last-Event-ID：https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events
- [R26] iOS Background Tasks：https://developer.apple.com/documentation/backgroundtasks
- [R27] Android Background Tasks：https://developer.android.com/develop/background-work/background-tasks

### 协议与其他 Agent

- [R28] Gemini CLI：https://github.com/google-gemini/gemini-cli
- [R29] Aider：https://github.com/Aider-AI/aider
- [R30] Goose：https://github.com/block/goose
- [R31] Agent Client Protocol：https://agentclientprotocol.com/protocol/overview
- [R32] Termius Mobile Terminal：https://docs.termius.com/terminal/mobile-terminal.md
