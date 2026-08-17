# Nomad Validation Companion PRD

| 字段 | 内容 |
| --- | --- |
| 状态 | Draft 0.1 |
| 日期 | 2026-08-11 |
| 目标发布 | Validation Companion Private Alpha，具体日期由验证阶段决定 |
| 产品 DRI | 角色：产品负责人；Discovery 启动前必须登记到具体人 |
| 技术 DRI | 角色：技术负责人；Dual Spike 启动前必须登记到具体人 |
| 安全 DRI | 角色：安全负责人；协议实现前必须登记到具体人，顾问不能代替内部 DRI |

## 1. 目的

验证高频 OpenCode CLI 用户是否会持续使用手机推进本机任务，并证明 Nomad 能在真实网络环境下安全、准确地同步 Agent 会话。这个版本验证 Companion，不验证自有 Agent Runtime 是否已经完成。

MVP 完成后，用户应能做到：

1. 在电脑上安装固定支持版本的 OpenCode 和 Nomad Host Connector，从 OpenCode CLI 启动任务。
2. 将一台手机与电脑配对。
3. 离开电脑后查看同一任务的实时状态和结构化过程。
4. 在手机上回答问题、批准一次操作、拒绝或停止任务。
5. 查看文件改动和测试结果。
6. 经历断网、切换网络或 App 被系统挂起后，恢复到准确状态。

## 2. MVP 定义

这里的 MVP 指可供外部设计伙伴连续使用四周的 Validation Companion，不是演示原型，也不是最终 Runtime。

MVP 由四部分组成：

| 组件 | 职责 |
| --- | --- |
| OpenCode + Host Connector | OpenCode 负责 Agent；Connector 固定其版本、转换协议、配对设备和连接 Relay |
| Secure Relay | 设备发现、在线状态、密文路由、短期密文补发和通用 Push |
| Mobile Companion | 查看、回复、审批、Diff、Stop 和设备管理 |

Validation Companion 全程使用固定 OpenCode 版本。若产品门通过而原生内核门不通过，它可以继续迭代并独立发布；若产品门、原生内核门和安全架构门都通过，再启动单独的 Runtime Alpha。两者不能共享“已完成自有 Runtime”的对外表述。

Runtime Alpha 的增量范围是：单 Provider 路径、核心只读/编辑工具、Session/Event 唯一 writer 和隔离 worktree。它不属于本 PRD 的发布门槛，详见路线图。

## 3. 目标用户与场景

### 3.1 用户资格

Private Alpha 用户应满足以下条件：

- 每周至少三次使用 CLI code agent。
- 最近两周至少有三次单任务运行超过十分钟。
- 使用 Apple Silicon Mac；电脑在测试任务期间可以保持开机联网。
- 已经使用固定支持版本的 OpenCode，愿意接受安装本地 Connector。
- 有 iPhone，愿意通过测试渠道安装 App 并开启通知。

选择单平台是资源约束，不代表长期平台优先级。Discovery 若显示首要用户明显不符合该组合，阶段门前重审，不在实现中同时扩成四个平台。

### 3.2 核心场景

| 优先级 | 场景 | 用户结果 |
| --- | --- | --- |
| P0 | 离桌后查看任务 | 清楚知道运行、等待、完成、失败或离线 |
| P0 | 处理权限请求 | 看懂 Host 已知输入和影响；始终可拒绝/Stop，通过权限与安全双门后可允许一次 |
| P0 | 回答 Agent 问题 | 手机回复进入正确会话且只提交一次 |
| P0 | 纠偏或止损 | 排队补充指令，或停止当前 turn 后再发指令 |
| P0 | 审阅结果 | 查看文件统计、逐文件 diff 和测试摘要 |
| P0 | 弱网恢复 | 自动补齐事件，不丢消息、不重复执行 |
| P1 | 多台电脑切换 | 在机器列表中选择正确主机和会话 |
| P1 | 语音输入 | 语音转成可编辑文本，确认后发送 |

## 4. 范围

### 4.1 P0 范围

#### Host Connector

- 仅支持 Apple Silicon macOS 和一个固定 OpenCode 版本。
- 管理 OpenCode loopback Server 的发现、认证和版本检查，不向公网暴露其端口。
- 将 OpenCode Session、message、tool、permission、diff 和状态转换为 Session Semantics v0；跨网消息使用安全门后冻结的 Security Envelope v0。
- 支持当前 turn Stop、普通消息排队和 `interrupt and send`；最终状态以 Host 确认为准。
- 保存 Connector 自己的密文传输游标、设备信息和恢复快照，不成为 OpenCode Session 数据的第二 writer。
- 在 Session 开始时记录 workspace 基线；检测外部编辑并明确标记“workspace diff，无法完全归因于本 Session”。
- `nomad pair`、`nomad devices`、`nomad revoke <device>` 和 `nomad doctor`。
- 活跃 Session 可选择阻止系统自动睡眠；合盖、手动睡眠和断电仍会中断连接，界面提前说明。

#### 移动端

- 仅 iOS 测试分发。具体使用 React Native 还是原生由技术 spike 决定。
- 登录、扫描二维码配对、设备密钥保存和设备吊销。Private Alpha 用户范围是一台 Host 加一台 iPhone；第二台测试设备只用于自动化和安全竞争测试，不是用户 P0。
- 单 Host 信息、Session 列表和状态筛选。
- Session timeline、流式文本、工具状态、错误和测试结果。
- 文本输入、排队发送、停止并发送。
- Permission 卡片：拒绝、停止当前 turn；只有 Fixed OpenCode Adapter 阻断验证和安全门都通过后才显示“允许一次”。
- Diff 总览、文件列表、统一 diff、二进制和超大文件提示。
- Push：需要权限、需要回答、完成、失败。
- Live、Reconnecting、Offline、Stale 四种连接状态。
- App 回前台后自动按游标和快照恢复。
- 生物识别保护“允许一次”和设备设置。无法确定影响范围的高风险操作不能在手机允许。

#### Relay 与安全

- Host 只建立出站 TLS/WSS 连接，不要求公网端口。
- 消息、路径、仓库名、命令、diff、工具结果均为应用层密文。
- 每台设备独立身份密钥，支持单设备吊销。
- 事件按 Session 单调递增序号传输，命令使用幂等键。
- Relay 可短期保存密文，默认七天或全部已注册设备确认后清理，以较早条件为准。
- Push 不包含源码、路径、命令、Prompt 或 diff。
- 审批绑定 Session、turn、工具参数、工作目录、基准版本、有效期和 action hash。
- 命令采用至少一次传递，并以 request ID 去重“启动执行”。本机工具在外部副作用成功后、结果落库前崩溃时进入 `OutcomeUnknown`，不会自动重跑。
- Validation Companion 不提供密钥恢复。全部可信设备丢失后，用户重新配对，但不能恢复 Relay 上的历史密文。

### 4.2 P1 范围

P1 只在 P0 发布门槛不受影响时进入 Private Alpha：

- 图片或文本附件。
- Web 只读 fallback。
- Push-to-talk 语音转文字草稿。
- Session 导出为开放 JSON。
- Tailscale 或局域网直连模式。
- 自动生成 Session 标题和简短完成摘要。

### 4.3 明确排除

- 完整移动 IDE、移动代码编辑器、Debugger、LSP UI。
- 默认开放的 PTY、SSH 或任意远程 shell。
- 手机端创建任意目录中的新任务。
- 电脑休眠或关机后的云端续跑。
- 多用户协作、公开分享、团队审批链。
- 原生桌面 App、IDE 扩展和插件市场。
- Provider OAuth、模型订阅账户复用和 75+ Provider。
- JavaScript 插件、Custom Tool 动态加载、完整 OpenCode 配置兼容。
- 自有 CLI/TUI、Provider adapter、工具执行和 Session 数据库。
- 多 Agent 编排、后台 Subagent 团队和云沙箱。
- Android、Intel Mac、Linux 和 Windows 客户端。
- 同一账户多台 Host。
- 手机设置永久全局权限规则或 bypass permission。
- 锁屏通知上的一键批准。
- 离线排队审批、Stop 或 Terminate。
- 第三方语音 Agent 读取完整 Session 上下文。

## 5. 信息架构

### 5.1 移动端

| 页面 | 主要内容 | 主要操作 |
| --- | --- | --- |
| Home | 需要处理、运行中、最近完成的 Session | 打开 Session、切换机器 |
| Host | 机器在线状态、版本、供电/睡眠提示、最后连接时间 | 查看 Session、吊销 Host |
| Session | Timeline、当前状态、输入框 | 回复、排队、停止、打开 diff |
| Changes | 文件统计、文件列表、逐文件 diff、测试摘要 | 切换文件、标记已看 |
| Approval | 工具、参数、cwd、风险、影响范围、过期时间 | 允许一次、拒绝、Stop |
| Devices | 已注册手机和主机、最后使用时间 | 吊销设备、重命名 |
| Settings | 通知、隐私、诊断、自动锁定 | 修改本设备设置 |

Home 首屏先展示“需要我处理”的 Session，其次是运行中。已完成和失败归入最近活动，避免把移动端做成聊天历史列表。

### 5.2 Connector CLI

候选命令面如下，最终名称在 CLI 原型测试后冻结：

```text
nomad connect                      # 连接或启动受支持的本地 OpenCode Server
nomad pair                         # 显示二维码和短期配对码
nomad devices
nomad revoke <device-id>
nomad doctor                       # 诊断 Connector、OpenCode 版本、Relay 和通知
nomad disconnect                   # 停止 Connector，不停止 OpenCode Session
```

Agent 的创建、恢复、模型和工具仍由 OpenCode CLI 管理。Connector 不复制这些命令。

## 6. 核心状态模型

### 6.1 正交状态

客户端必须同时维护三个状态，不能把执行结果、Host 在线性和客户端数据新鲜度压进一个枚举。

| 维度 | 状态 | 含义 |
| --- | --- | --- |
| `turn_state` | None | Session 没有活动 turn |
| `turn_state` | Running | 模型或工具正在执行 |
| `turn_state` | NeedsInput | Agent 等待用户回答 |
| `turn_state` | NeedsPermission | 工具等待审批 |
| `turn_state` | Stopping | Host 已接纳 Stop，等待执行结束 |
| `turn_state` | Completed | Turn 正常结束 |
| `turn_state` | Cancelled | Turn 被确认取消 |
| `turn_state` | Failed | Turn 因已知错误结束 |
| `turn_state` | OutcomeUnknown | 可写工具可能已经产生外部副作用，但 Host 未能可靠记录结果 |
| `host_connectivity` | Online / Offline | Host heartbeat 是否在有效窗口内 |
| `client_freshness` | Live / Reconnecting / Stale | 当前客户端是否完成事件 gap 与快照校验 |

只有 `host_connectivity=Online` 且 `client_freshness=Live` 时，手机才能提交 Approval 或 Stop。Completed 等是 Turn 结果，不是 Session 终态；Session 可以继续产生新 Turn。

### 6.2 事件类型

持久事件至少包括：

```text
session.created
session.updated
turn.started
message.accepted
message.completed
tool.started
tool.completed
tool.failed
permission.requested
permission.resolved
diff.updated
turn.stopping
turn.completed
turn.cancelled
turn.failed
turn.outcome_unknown
session.compacted
```

文本 delta、工具输出 delta、typing 和 presence 可以是瞬时事件。每个持久事件有 `session_id`、`turn_id`、`event_id`、`seq`、版本、时间戳和密文 payload。客户端不能用瞬时 delta 作为恢复后的最终事实。

## 7. 关键用户流程

### 7.1 首次安装与配对

1. 用户安装固定支持版本的 OpenCode，并在 OpenCode 中完成 Provider 配置和一次只读试运行。
2. 用户安装 Nomad Connector，在项目目录运行 `nomad connect`；Connector 检查 OpenCode 版本并连接只绑定 loopback 的 Server。
3. Connector 显示当前 Session 和连接状态，但不读取 Provider API Key。
4. 用户运行 `nomad pair`，终端显示二维码、六位比对码和两分钟倒计时。
5. 用户在移动 App 登录并扫描二维码。
6. 手机和终端显示同一比对码，以及对方设备名称。
7. 用户在两端确认，设备交换公钥并注册。
8. 手机出现机器和当前 Session；终端显示设备名称与吊销命令。

验收标准：

- 扫码到机器可用 P50 少于 30 秒，P90 少于 60 秒。
- 二维码单次使用，两分钟过期，不含长期 bearer token。
- 任一端未确认或比对码不一致时，配对不能完成。
- 重放、过期、已消费二维码均被拒绝，并留下不含内容的安全日志。
- 首次配对失败时提供具体恢复方式，不要求用户手动处理端口或证书。

### 7.2 离桌后处理权限

1. Agent 在本机准备执行需要审批的操作。
2. OpenCode 创建唯一 pending permission 和 upstream permission ID。Connector 读取原始请求，判断它是否属于远程可批准集合，并生成规范化输入、已知资源、action hash 和过期时间。
3. 手机收到通用 Push：“一项任务需要处理”。
4. 用户打开 Approval 页面，看到 Host 观察到的工具、完整输入、cwd、已知资源和风险提示。界面不声称能预测任意程序的全部副作用。
5. 用户选择允许一次或拒绝；允许一次要求生物识别。高风险或影响范围不确定的请求没有允许入口。
6. 手机签名决定，Relay 转发密文。
7. Connector 检查设备、状态、action hash、有效期和 pending 是否仍为同一个 upstream request，再将决定回传 OpenCode。
8. OpenCode 原子解决 pending permission 并执行或拒绝；Connector 从 OpenCode 事件或快照确认唯一结果，再同步所有客户端。

验收标准：

- 从点击 Push 到卡片可操作 P95 少于 5 秒。
- 审批回传到 Host 接受 P95 少于 2 秒。
- 展示内容不能由模型文本替代；模型解释须标为“不可信说明”。
- 参数、工作目录、可执行文件、引用脚本内容或基准版本变化后，旧决定失效并重新请求。
- 两台设备竞争处理时只接受第一个合法决定，另一台显示处理人和结果。
- 过期或离线状态下不能提交允许决定。
- 同一 request 重试一百万次的自动化测试中，Host 最多启动一次本地工具执行。崩溃窗口内结果不明的工具进入 `OutcomeUnknown`，不得自动重跑。
- 含 shell 组合、解释器、重定向、命令替换、动态下载，或无法绑定可执行文件和脚本 hash 的请求不能在手机允许，只能拒绝、Stop 或回桌面处理。
- Fixed OpenCode Adapter 必须通过发布门中的权限阻断验证。若不能保持同一 pending request、原子竞争和 fail closed，手机只保留查看、拒绝和 Stop，不提供“允许一次”。

### 7.3 补充指令与纠偏

1. 用户在 Running 状态输入补充指令。
2. 默认动作是“排队”，客户端显示发送中、已接收、等待处理和已应用。
3. 用户可以选择“停止当前步骤并发送”。
4. Connector 向 OpenCode 请求 Stop；确认 OpenCode Turn 进入 Stopping/Cancelled 后再提交新消息。
5. 若 Host 离线，普通文本保留为本机草稿，不上传为待执行命令。

验收标准：

- 每条输入有客户端生成的幂等键，网络重试不能产生重复消息。
- `interrupt and send` 不允许出现旧 turn 和新 turn 同时修改文件。
- 用户能区分“Relay 已接收”和“Host 已接纳”。
- Host 离线、Session Stale 或权限上下文变化时，不假装消息已应用。

### 7.4 查看 Diff 与完成结果

1. Connector 在文件改动后更新相对于 Session 启动基线的 workspace diff。
2. Changes 首屏展示新增、修改、删除文件数和测试状态。
3. 用户按文件打开统一 diff，超大文件按块加载。
4. 二进制、生成文件、重命名和工作区外改动单独标识。
5. 用户可以继续发送指令，不能直接在手机编辑 diff。

验收标准：

- 100 个文件、1 万行 diff 的文件列表 P95 少于 1 秒，首个文件 P95 少于 2 秒。
- 单个超大 diff 不导致 App 卡死；滚动使用虚拟化。
- Diff 必须对应明确的 Git 与 workspace 基准，基准变化时提示刷新。
- 未跟踪文件、删除和重命名不会被漏掉。
- 测试状态区分通过、失败、取消、未运行和结果过期。
- 检测到用户、其他 Session 或外部进程修改时，界面标记“workspace diff，无法完全归因于本 Session”，不把这些变化描述成 Agent 产出。

### 7.5 弱网与恢复

1. 前台 WSS 断开后，客户端在两秒内显示 Reconnecting 或 Stale。
2. 用户从 Wi-Fi 切到蜂窝网，或 App 被系统挂起。
3. 回前台后客户端携带 `last_applied_seq` 请求恢复。
4. Relay 或 Host 返回缺失持久事件，并用快照校验状态。
5. 客户端处理完成后才恢复 Live 和安全操作。

验收标准：

- 短断网恢复 P95 少于 3 秒。
- 自动故障注入按验证计划的统一口径测试；八小时恢复报告成功/失败原始次数，不用小样本宣称 99.5%。
- 快照校验后不能存在未解释的持久事件缺口、乱序或重复投影。
- Approval、Stop 和 Terminate 不做离线排队。
- Push 晚到或重复到达时，已解决请求不会再次可操作。

## 8. 权限与风险模型

### 8.1 默认策略

| 操作 | 默认行为 |
| --- | --- |
| 读取、搜索 workspace 内普通文件 | 允许，但敏感路径和文件模式默认拒绝 |
| 修改 workspace 内文件 | Session 启动时由用户选择，推荐允许并通过 diff 审阅 |
| 明确的只读 Git 和项目状态命令 | 允许，规则需经过安全测试 |
| 精确文件编辑 | 可远程询问，决定绑定目标路径、基准和 patch hash |
| 无 shell 组合的直接进程调用 | 只有匹配桌面预设 allowlist，并绑定 executable、args 和引用脚本 hash 时可远程询问 |
| 测试、构建和格式化 | 不满足上一条时回桌面处理 |
| 网络访问、包安装、Git push | Validation Companion 不能从手机允许 |
| workspace 外写入、凭据目录、系统目录 | 拒绝或回桌面处理 |
| 提权、批量删除、强制推送 | 手机拒绝或 Stop，不能允许 |
| 任意 shell、动态脚本或无法规范化的命令 | Fail closed，回桌面处理 |

移动端只有“允许一次”和“拒绝”，不能新建 Session 或永久规则。规则只能从本机设置。

Connector 为测试用户检查并建议启用 OpenCode 本地权限配置，默认拒绝读取 `.env*`、私钥、云凭据目录、Git 凭据和常见 Token 文件。用户只能在本机修改这些规则。Validation Companion 不控制 OpenCode 的 Provider 请求，无法承诺拦截工具输出或所有 Secret；这项能力必须在后续自有 Runtime 中实现并单独验收。

### 8.2 审批呈现

Approval 页面必须显示：

- 工具名称和规范化参数。
- 完整工作目录与目标路径。
- Host 已知的文件、网络目标或 Git remote；不能确定时明确显示“影响范围未知”并禁止手机允许。
- 风险级别，以及触发该级别的确定性规则。
- 允许决定的作用域和过期时间。
- 不可见字符、Unicode bidi 和 shell 控制字符警告。
- 模型生成的理由，若存在，必须与系统事实分区。

## 9. 功能需求

### 9.1 Host Connector

| ID | 需求 | 优先级 | 验收摘要 |
| --- | --- | --- | --- |
| HC-01 | 固定 OpenCode 版本适配 | P0 | 版本不匹配时停止可写远程操作 |
| HC-02 | 上游状态转换为 Session Semantics v0 | P0 | Golden trace 与 Host 快照一致 |
| HC-03 | OpenCode 只绑定 loopback | P0 | 外网扫描不能直接访问 OpenCode API |
| HC-04 | Stop、message 和 approval 去重 | P0 | 同一 request ID 最多被 Host 接纳一次 |
| HC-05 | Workspace 基线与外部变化检测 | P0 | 不可归因的改动有明确标识 |
| HC-06 | Sleep 抑制和状态提示 | P0 | 活跃任务期间可选保持唤醒，退出后恢复系统设置 |
| HC-07 | Bounded event/tool projection | P0 | 大输出不撑爆 Relay 或移动端 |
| HC-08 | 诊断与升级 | P0 | 可发现版本、网络、Push 和存储故障 |

### 9.2 跨端协议

| ID | 需求 | 优先级 | 验收摘要 |
| --- | --- | --- | --- |
| SP-01 | 持久事件有单调 seq 和版本 | P0 | 可检测 gap、重复和未知版本 |
| SP-02 | Snapshot 加增量恢复 | P0 | 断线后状态收敛一致 |
| SP-03 | 命令接纳去重 | P0 | 重试不重复启动同一 Host 操作；结果未知时不自动重跑 |
| SP-04 | 内容 E2EE | P0 | Relay 数据库和日志无可解密内容 |
| SP-05 | 每设备身份与吊销 | P0 | 吊销后 P95 60 秒内失效 |
| SP-06 | Presence 与持久事件分离 | P0 | 瞬时事件丢失不破坏最终状态 |
| SP-07 | 协议版本协商 | P0 | 版本不兼容时明确阻止安全操作 |

### 9.3 移动端

| ID | 需求 | 优先级 | 验收摘要 |
| --- | --- | --- | --- |
| MB-01 | Home 按待处理优先排序 | P0 | 用户无需翻找阻塞 Session |
| MB-02 | 结构化 Timeline | P0 | 不直接渲染未过滤 ANSI/OSC |
| MB-03 | Approval 卡片 | P0 | 与 action hash 对应，过期不可点 |
| MB-04 | Diff 浏览 | P0 | 大 diff 可用，内容与基准一致 |
| MB-05 | Queue、interrupt、Stop | P0 | 区分 Relay 收到、Host 接纳和最终结果 |
| MB-06 | Push 与 deep-link | P0 | 无内容泄露，准确进入 Session |
| MB-07 | App 锁和安全存储 | P0 | 私钥不以普通文件保存 |
| MB-08 | 语音草稿 | P1 | 不直接执行或批准 |

## 10. 非功能需求

### 10.1 性能目标

这些是内部验收目标，测试时必须记录硬件、OS、仓库 fixture 和 Provider 条件。

| 指标 | MVP 目标 |
| --- | --- |
| Connector 到 Ready | 参考机器 P95 少于 1 秒，不含 OpenCode 启动 |
| Connector 空闲资源 | CPU 少于 1%，RSS P95 少于 75 MB |
| 十万持久事件恢复到移动快照 | P95 少于 2 秒，峰值 RSS 少于 200 MB |
| 前台 Host 到手机事件延迟 | 同区域 P50 少于 250 ms，P95 少于 800 ms |
| 网络恢复到 Live | P95 少于 3 秒 |
| Stop 到本机发出取消信号 | P95 少于 1 秒 |
| 八小时长会话 | 无持续 RSS、FD 或任务泄漏趋势 |

Rust 是否进入后续 Runtime Alpha 不属于本 PRD 的验收项。基准必须在运行前冻结 3 至 5 个产品 workload、权重和非退化预算；至少一个用户关键 workload 达到 2 倍提升或峰值 RSS 降低 40%，其余关键 workload 不超出预算，且兼容和崩溃一致性全部通过。

### 10.2 可靠性目标

| 指标 | Private Alpha | Beta 候选 |
| --- | --- | --- |
| Crash-free Companion Session | 报告原始次数；至少 100 个 Session 后参考 99.0% | 至少 99.8% |
| 恢复后持久事件缺口 | 0 | 0 |
| 同一 request 被 Host 启动两次 | 0 | 0 |
| 自动故障注入恢复 | 600 次以上独立机会，报告成功/失败 | 至少 99.5% |
| 真实用户恢复 | 报告成功/失败次数和逐次复盘 | 足量样本后设 SLO |
| Push Provider 接受率 | 至少 99.0% | 至少 99.5% |
| App receipt / 前台校准 | 报告已开启通知设备的成功/失败和耗时 | Closed Beta 前设目标 |

### 10.3 隐私与安全

- Connector、Mobile、Protocol 和 Relay 在外部 Alpha 前完成威胁建模。
- 加密使用成熟库和协议，不自研 cipher。
- 私钥存入 macOS Keychain、iOS Keychain/Secure Enclave 或同等级系统设施。
- Relay 日志、分析和 Crash Report 默认不包含 Prompt、代码、路径、命令和工具输出。
- 诊断包由用户主动生成，上传前可预览，敏感字段默认脱敏。
- App 切换器预览隐藏代码内容，后台一段时间后自动锁定。
- Release 产物签名，提供 SBOM，依赖和许可证持续扫描。
- Private Alpha 前通过独立安全架构门，冻结账户身份、信任根、设备加入、历史密文访问、吊销后密钥轮换和全部设备丢失后的行为。远程审批和设备配对是必审范围。

### 10.4 可访问性

- 移动端支持系统字体缩放、屏幕阅读器和减少动态效果。
- 状态不只依赖颜色，Diff 增删有符号和文字。
- 常用审批操作触控区域至少 44 x 44 pt。
- 高风险允许与拒绝保持足够距离，不使用容易误触的滑动手势。

## 11. 数据与分析

### 11.1 Provider 与平台数据边界

| 处理方 | 可以看到 | 默认看不到 |
| --- | --- | --- |
| 用户选择的模型 Provider | OpenCode 为推理选择的指令、代码片段、工具结果和模型请求元数据 | 未被选入上下文的仓库文件、Nomad 设备私钥 |
| Nomad Relay | 化名账户/设备/Session ID、IP、时间、消息大小、在线状态、Push token、密文 | Prompt、回复、路径、仓库名、命令、diff 和工具正文 |
| APNs | 设备 Push token、通用通知类别和 opaque deep-link | 代码、路径、命令、Prompt 和 diff |
| Nomad 遥测 | 下节列出的化名化事件和性能直方图 | Session 正文和具体工具参数 |

首次连接 Provider 时必须明确说明：BYOK 不等于内容不离开本机，选入模型上下文的数据受该 Provider 的数据政策约束。Nomad E2EE 保护的是 Host、Relay 和已授权客户端之间的链路，不覆盖模型 Provider 收到的请求。

### 11.2 允许采集

- 安装、配对、连接、恢复和 Push 的成功或失败码。
- Session 的化名化状态转换和时长区间。跨周留存使用随机稳定 ID，不称为匿名数据。
- 工具类别，不含参数、命令、路径和输出。
- 移动操作类别，例如 reply、allow once、deny、stop、open diff。
- 客户端版本、OS 大版本、网络类型和性能直方图。
- Crash stack，前提是经过内容清理。

### 11.3 禁止采集

- Prompt 和模型回复正文。
- 源代码、diff、文件名、完整路径和仓库名称。
- Shell 命令、工具参数和环境变量。
- API Key、Token、凭据文件和 Git remote URL。
- 未经明确同意的 Session 录屏或原始日志。

### 11.4 数据保留与删除

| 数据 | 默认保留 | 删除行为 |
| --- | --- | --- |
| 本地 OpenCode Session | 遵循 OpenCode 本地设置 | 由用户在本机管理 |
| Connector 加密快照和待发送事件 buffer | 在线同步后清理 buffer；快照保留到 Session 删除或 7 天未访问 | `nomad disconnect --forget`、卸载并选择删除数据或账户删除时清除 |
| Connector 本地安全日志 | 不含正文，保留 30 天 | 卸载并选择删除数据或账户删除时清除 |
| Mobile 加密 timeline/diff cache | 最近 7 天或本地存储上限 | 退出登录、设备吊销、账户删除或卸载时清除 |
| Mobile 未发送草稿 | 仅本机，保留到用户发送或删除 | 退出登录、设备吊销或卸载时清除 |
| Relay 会话密文 | 7 天或所有目标设备 ACK，以较早者为准 | 账户删除立即标记，备份最长 30 天清除 |
| Relay 路由/安全元数据 | 30 天 | 账户删除后 30 天内清除，法定义务除外 |
| 化名化产品遥测 | Private Alpha 需明确同意，保留 90 天 | 账户删除后 30 天内清除可关联记录 |
| Crash report | 用户主动同意，保留 30 天 | 可按报告 ID 提前删除 |
| 用户上传诊断包 | 14 天 | 支持工单关闭或用户请求后提前删除 |
| APNs 数据 | 遵循 Apple 政策 | Nomad 立即删除已吊销设备的 token |

Private Alpha 只有接受化名化可靠性遥测的用户进入量化 cohort；拒绝的用户仍可使用，但只进入定性研究。数据删除验收必须覆盖主库、缓存、分析系统和备份生命周期。

### 11.5 关键漏斗

```text
connector_installed
→ supported_opencode_connected
→ first_local_session_observed
→ device_paired
→ first_remote_session_viewed
→ first_remote_action_completed
→ second_week_remote_action
→ fourth_week_retained
```

远程审批数量不是成功指标。团队要同时观察每 Session 审批数量、拒绝率、误触反馈和因权限等待节省的时间，防止通过制造更多弹窗提高使用量。

## 12. 错误与边界体验

| 情况 | 用户看到什么 | 系统行为 |
| --- | --- | --- |
| Host 将自动睡眠、合盖或关机 | 先提示任务会中断；离线后显示最后在线时间 | 活跃任务可选阻止自动睡眠；合盖/手动睡眠后禁止审批和 Stop |
| Provider 限流 | 明确 Provider、可重试时间 | 保留 Session，不自动无限重试 |
| Relay 不可达 | 本地任务继续，移动端 Stale | Host 缓存有限事件，恢复后补发 |
| App 版本过旧 | 只读或强制升级提示 | 不允许发送不兼容的安全命令 |
| Permission 已在桌面处理 | 显示已处理和结果 | Push 撤销或 deep-link 到结果 |
| Diff 基准变化 | 提示内容已过期 | 重新计算后才能继续展示 |
| 磁盘不足或 DB 失败 | 本地显著报错，移动端 Failed | 停止接纳可写任务，避免伪成功 |
| Connector 或 OpenCode 崩溃 | 显示重启与恢复状态 | 重新读取 Host 快照；结果不明的可写工具标记 `OutcomeUnknown`，不自动重跑 |

## 13. 发布门槛

缺陷分级以用户影响为 P0/P1/P2，安全漏洞另用 Critical/High/Medium/Low：

| 分级 | 示例 | 发布规则 |
| --- | --- | --- |
| 产品 P0 | 数据损坏、核心闭环不可用、无替代路径 | 0 个 |
| 产品 P1 | 核心场景明显受损但有安全降级或明确 workaround | 可由产品 DRI 和技术 DRI共同接受 |
| 安全 Critical/High | 跨会话审批、密钥或内容泄露、认证绕过、同一 request 启动两次 | 0 个，不接受临时缓解后发布 |
| 安全 Medium | 需要前置条件、影响受限但违反威胁模型 | Private Alpha 前 0 个；后续阶段只有安全 DRI 和独立评审者共同确认风险接受时可延期 |
| 安全 Low | 不改变安全边界的纵深防御问题 | 必须有 Owner 和修复日期 |

安全 DRI 负责初始定级，并有停止发布权；争议由独立安全评审者复核。产品 DRI 不能下调安全等级。

Private Alpha 开放给外部用户前必须同时满足：

- P0 用户流程在 Apple Silicon macOS 和 iOS 的支持矩阵上通过。
- Session Semantics v0、Security Envelope v0 和 OpenCode adapter contract 已冻结，Connector 与 Mobile 使用同一版本模型。
- D-005 安全架构门转为 `Accepted`，并在决策记录中写明信任根、设备加入、吊销轮换和无密钥恢复行为。
- Fixed OpenCode Adapter 已证明 permission 只有一套 pending 状态、手机与桌面原子竞争、Connector 断线时 fail closed；否则产品范围已降级为查看、拒绝和 Stop。
- 至少完成 600 次预先登记的自动恢复机会，以及 20 次八小时恢复，无持久事件缺口；两类结果分别报告。
- 审批重放、双设备竞争、参数变化和过期测试全部通过。
- Connector 强杀、OpenCode 重启和 Relay 重连测试后，事件与 Host 快照收敛一致。
- Push payload 自动扫描未发现内容字段。
- 完成内部威胁建模和一轮独立安全架构评审。
- 10 名内部或友好用户连续使用两周，其中至少 8 人完成跨端闭环。
- 安装、卸载、设备吊销和数据删除路径可用。
- `nomad doctor` 能覆盖已知高频故障，并生成不含内容的诊断包。
- 已知产品 P0、Security Critical/High/Medium 为 0；产品 P1 按上表接受，Security Low 有 Owner 和修复日期。

## 14. MVP 成功与停止条件

Private Alpha 运行四周后，满足以下条件才进入 Closed Beta：

- 至少 30 名合格用户完成首次本地 Session，20 名完成首次跨端闭环。
- 20 名跨端激活用户中至少 8 名在第 4 周仍完成一次远程推进或止损；同时访谈全部流失用户，不把 40% 当作小样本统计结论。
- 留存用户中至少 5 人每周在两个不同日期执行远程操作。
- 至少记录 20 个 Host 在线且符合远程处理范围的 Permission 或 Question，其中至少 16 个不需回电脑解决；忽略和过期均进入分母。
- 没有跨会话审批、同一 request 启动两次或 Nomad 数据边界内的内容泄露事故。
- 用户访谈中，“不必回电脑解除阻塞”是自发提到的前三项价值之一。

出现以下任一情况，暂停扩范围并先修正：

- 任何跨会话审批、审批内容与 Host 实际接纳动作不一致，或同一 request 启动两次。
- 出现任何无法解释的恢复失败；修正并重新完成发布门的故障注入样本后才能继续扩量。
- 用户主要把 App 当完成通知，极少回复、审批或看 diff。
- 多数用户仍选择 SSH/远程终端完成相同任务，原因是结构化 UI 信息不足。
- 为达到可接受能力被迫复制完整 OpenCode 生态，导致核心闭环无法按期验证。

Private Alpha 以绝对人数和流失访谈决策。累计至少 60 名跨端激活用户后，如果两轮产品修正的第 4 周留存仍低于 20%，停止独立移动产品投入，重新评估 Companion、纯 Runtime 或终止项目。

## 15. 待决问题

| 问题 | DRI | 最晚决定点 | 所需证据 |
| --- | --- | --- | --- |
| React Native 还是原生 iOS | Mobile DRI | Mobile spike 结束 | 大 diff、流式列表、Push、后台和密钥存储原型 |
| 何时增加 Android 与其他 Host OS | 产品 DRI | Closed Beta 规划前 | 目标用户设备分布、流失原因和各平台维护成本 |
| 哪些结构化工具进入远程 allowlist | 安全 DRI | Private Alpha 前 | Threat model、误审批测试和可绑定的输入/资源 hash |
| Runtime Alpha 的单一 Provider 路径 | 技术 DRI | Runtime Alpha 启动前 | 设计伙伴使用分布、协议稳定性和实现成本 |
| Rust 内核是否进入默认构建 | 技术 DRI | Native Runtime Spike 后 | 预登记 workload、稳定性和团队维护成本 |
| 何时提供密钥恢复 | 安全 DRI | Closed Beta 规划前 | 恢复码/可信设备威胁模型和用户测试 |
| Community 版是否包含完整自托管中继 | 产品 DRI | Closed Beta 前 | 运维成本、采用和商业边界 |
