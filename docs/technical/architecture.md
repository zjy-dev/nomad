# Nomad 产品技术架构

| 字段 | 内容 |
| --- | --- |
| 状态 | Proposed 0.1 |
| 日期 | 2026-08-17 |
| 适用范围 | Validation Companion；条件满足后扩展到 Runtime Alpha |
| 输入 | `docs/product/` 下的产品战略、PRD、路线图、验证计划、调研和决策记录 |
| 目的 | 将产品约束转换为可验证、可演进、可并行实现的系统边界 |

## 1. 架构结论

Nomad 首先应被实现为一套围绕持久 Session 的跨端控制系统，而不是一套远程终端，也不是立即重写的 code agent。

Validation Companion 的权威链路是：

```text
OpenCode（唯一 Session 领域 writer）
  -> Host Connector（反腐层、协议投影、命令仲裁、本机最终裁决）
  -> Secure Relay（身份、密文路由、短期密文邮箱、通用 Push）
  -> Mobile Companion（本地投影、短时决策界面）
```

技术架构采用以下核心约束：

1. `Session Semantics` 与 `Security Envelope` 分层。前者定义业务事实，后者定义这些事实如何被认证、加密和防重放。
2. OpenCode 是 Validation Companion 阶段唯一的 Session 事实源；Connector 只持有 Nomad 投影、传输游标、命令日志和设备状态。
3. Relay 永远不是 Session 状态机。它可以知道路由元数据，但不能解密、解释或改写 Session 内容。
4. Mobile 通过确定性 reducer 从快照和持久事件得到状态；瞬时 delta、Push 和 presence 都不能成为最终事实。
5. 所有产生副作用的远程动作都由 Host 重新校验并最终裁决。Relay 收到、Host 接纳和执行完成是三个不同状态。
6. Validation Companion 与 Runtime Alpha 共享语义协议和客户端投影，不共享“已经完成自有 Runtime”的产品表述。
7. Rust Runtime 只在独立基准、兼容性和安全门通过后进入产品路径。

## 2. 从产品愿景到架构驱动力

| 产品要求 | 架构响应 | 可验证结果 |
| --- | --- | --- |
| local-first | 仓库、工具、Provider 凭据和最终命令裁决留在 Host | Relay 泄露不暴露内容；Host 离线时不伪装可执行 |
| 同步 Session，不镜像终端 | 结构化事件、快照、游标和客户端 reducer | 断线后状态收敛；不依赖 ANSI/PTY 重放 |
| 手机用于两分钟内推进任务 | Mobile 只承载状态、reply、受限 approval、diff 和 Stop | 核心流程可在小屏完成，不扩成移动 IDE |
| 弱网可恢复 | 每 Session 单调 `seq`、snapshot digest、gap 检测和幂等命令 | 重连后无未知 gap、乱序投影或重复接纳 |
| 安全决策由本机裁决 | action hash、有效期、当前 pending request 和 Host 快照复核 | 旧审批、跨会话审批和参数变化审批全部失效 |
| 中继看不到正文 | 应用层 E2EE、内容无关 Push、密文短期存储 | Relay 数据库和日志不能还原 Prompt、路径、命令或 diff |
| 性能必须可测 | 固定 fixture、可复现 workload、分位数和 soak/crash 测试 | Rust 与基线以相同 durability 和数据集比较 |
| OpenCode 只用于验证 | 固定版本 adapter 和反腐层 | Mobile 不依赖上游私有事件；后续可替换 Session owner |

## 3. 范围与演进边界

### 3.1 当前必须设计的系统

- Apple Silicon macOS 上的 Host Connector 与 CLI。
- 固定 OpenCode 版本的 HTTP/SSE adapter。
- Session Semantics v0 和兼容性测试资产。
- 安全阶段门通过后冻结的 Security Envelope v0。
- 单区域起步、可水平扩展的 Secure Relay。
- iOS Mobile Companion。
- 配对、设备吊销、密文补发、Push、诊断、遥测和数据删除。
- 故障注入、协议一致性、安全和性能验证设施。

### 3.2 条件满足后才设计到实现细节的系统

- 自有 Runtime 的 Provider、工具执行和隔离 worktree。
- 第二移动平台或第二 Host OS。
- 自托管 Relay 的完整运维面。
- 密钥恢复、多 Host、多用户协作、远程新建任务。

### 3.3 明确不进入当前架构

- PTY/SSH 作为默认跨端协议。
- 云端续跑或托管开发环境。
- 手机端永久权限规则和任意 shell。
- Connector 与 OpenCode 同时写 OpenCode Session 数据库。
- Relay 端内容索引、搜索、摘要或审批判断。
- 为了复用代码而在 Host、Relay、Mobile 之间共享运行时数据库。

## 4. 系统上下文

```text
                         Model Provider
                     (OpenCode 直接访问)
                              ^
                              | selected context
                              |
Developer -> OpenCode CLI/TUI + loopback Server
                              | HTTP/SSE, loopback only
                              v
                    +--------------------+
                    |  Nomad Connector   |
                    | adapter / projector|
                    | command arbiter    |
                    | device + key store |
                    +--------------------+
                              | outbound WSS, E2EE payload
                              v
                    +--------------------+      +------+
                    |    Secure Relay    |----->| APNs |
                    | opaque mailbox     |      +------+
                    | routing / device   |
                    +--------------------+
                              | WSS + Push wake-up
                              v
                    +--------------------+
                    |  iOS Companion     |
                    | reducer / cache    |
                    | approval / diff    |
                    +--------------------+
```

信任边界：

- OpenCode 与 Connector 位于用户 Host 信任域，但 Connector 不读取 Provider API Key。
- Relay 和 APNs 属于不可信内容传输域；Relay 可见产品文档已声明的元数据。
- Mobile 是单独设备信任域，私钥进入系统安全存储，敏感操作受本地认证保护。
- 模型 Provider 是独立数据接收方，Nomad E2EE 不覆盖 OpenCode 发给 Provider 的上下文。

## 5. 逻辑组件

### 5.1 Host Connector

Host Connector 是 Validation Companion 的安全边界和反腐层，逻辑模块如下：

| 模块 | 职责 | 不负责 |
| --- | --- | --- |
| OpenCode supervisor | 发现 loopback Server、固定版本检查、健康状态 | 启动或代理模型 Provider 账户 |
| OpenCode adapter | 读取上游 Session/message/tool/permission/diff，屏蔽上游差异 | 将上游私有 schema 直接暴露给客户端 |
| Semantic projector | 规范化持久事件、分配 Nomad `seq`、生成快照和 digest | 成为第二套 OpenCode Session writer |
| Command arbiter | 去重 request、记录接纳状态、转发 reply/Stop/permission decision | 对外部副作用承诺 exactly-once |
| Approval verifier | 绑定 pending ID、参数、cwd、基准、版本、有效期和 action hash | 根据模型自然语言判断风险 |
| Workspace observer | 建立基线、计算 workspace diff、检测外部修改 | 声称所有改动均由 Agent 产生 |
| Sync client | 出站 WSS、加密、ACK、重连和有限本地 outbox | 在 Host 离线时由 Relay 代为执行 |
| Device manager | 配对、设备公钥、吊销和轮换触发 | 提供无条件密钥恢复 |
| Diagnostics | 版本、网络、存储、Push 链路检查和脱敏诊断包 | 上传 Session 正文 |
| Lifecycle | 可选 sleep inhibition、升级、卸载和数据清理 | 承诺合盖或关机继续运行 |

Connector 的本地持久化只允许保存：

- 上游游标与上游事件到 Nomad 事件的稳定映射。
- Nomad `seq`、快照、投影校验信息和有界传输 buffer。
- 命令 request journal、设备元数据、密钥引用和安全日志。
- workspace 基线与不可归因标记所需的最小元数据。

它不得修改 OpenCode 的领域表，也不得把 Nomad 投影反向当成 OpenCode 的事实源。

### 5.2 Secure Relay

Relay 在 Alpha 阶段采用“模块化单体 + PostgreSQL”的部署形态。逻辑模块保持独立接口，避免过早拆微服务：

| 模块 | 职责 | 数据性质 |
| --- | --- | --- |
| Identity/Device directory | 账户会话、设备公钥、状态和吊销版本 | 元数据 |
| Connection gateway | WSS 鉴权、心跳、限流、在线路由 | 短期元数据 |
| Opaque mailbox | 存储密文 frame、目标、TTL 和 ACK | 不可解密内容 |
| Pairing coordinator | 短期配对会话、单次消费和双端确认协调 | 短期元数据和不透明握手材料 |
| Push outbox | 事务化生成通用 APNs 通知、重试和失效 token 清理 | 无正文通知类别 |
| Retention worker | 按七天或全部目标 ACK 的较早条件删除密文 | 删除状态 |
| Operations | privacy-safe metrics、audit、rate limit 和 abuse control | 聚合或化名元数据 |

Alpha 不默认引入 Redis。在线连接表可先保留在 gateway 内存中，PostgreSQL 保存权威设备、mailbox、ACK 和 Push outbox；只有多实例 presence 和吞吐基准证明需要时再引入独立协调层。

密文采用有界 frame。大 payload 在 Host 加密前切块，每块独立编号并受完整性保护；Relay 只校验大小、数量、TTL 和路由字段。初始实现优先使用 PostgreSQL `bytea` 短期保存密文块，不在 Alpha 提前引入内容对象存储。

### 5.3 Mobile Companion

| 模块 | 职责 | 关键约束 |
| --- | --- | --- |
| Secure identity | 设备私钥、App lock、本地认证 | 私钥不进入普通文件或遥测 |
| Pairing client | QR 解析、短期握手、比对码和双端确认 | 过期、消费或不匹配立即失败 |
| Sync engine | WSS、解密、ACK、gap 检测、snapshot reconcile | 完成校验前不得显示 Live |
| Local cache | 加密 timeline/diff cache 与本机草稿 | 遵循七天/容量和吊销删除策略 |
| Session reducer | 用 snapshot + durable events 产生确定性视图 | ephemeral delta 丢失不改变最终事实 |
| Command client | request ID、签名、发送状态和最终结果 | Approval/Stop 不离线排队 |
| Presentation | Home、Session、Approval、Changes、Devices、Settings | 状态不只靠颜色；大列表虚拟化 |
| Push handler | 通用通知、opaque deep-link、前台校准 | Push 只唤醒，不声明最新状态 |

Mobile 技术栈仍需 spike 决定。无论采用原生 iOS 还是 React Native，上述模块边界、协议测试向量和安全存储要求不变。

### 5.4 条件式 Runtime Alpha

Runtime Alpha 是新的 Session owner，不是 Connector 内部的优化模块。它至少包含：

- Session/Event 唯一 writer 和 SQLite 事务边界。
- 单 Provider 路径。
- `read`、`glob`、`grep`、精确 edit 和受限直接进程工具。
- 每个可写 Session 的隔离 worktree。
- 与 Session Semantics v0 兼容的 adapter。

它不与 OpenCode 共写一个 Session，也不在迁移门前替换 Companion 用户的底层。

## 6. 协议分层

```text
Product semantics
  Session / Turn / Event / Snapshot / Command / Result
        |
Canonical encoding and compatibility
  schema version / unknown-field policy / chunking / limits
        |
Security envelope
  sender / recipient / key version / signature / nonce / expiry
        |
Transport
  WSS / mailbox / ACK / reconnect / Push wake-up
```

### 6.1 Session Semantics v0

语义层必须与加密和具体传输无关，包含：

- `session_id`、`turn_id`、`event_id`、每 Session 单调 `seq`。
- `turn_state`、`host_connectivity`、`client_freshness` 三个正交维度。
- durable event 与 ephemeral event 的分类。
- snapshot、`last_applied_seq`、snapshot digest 和 compaction boundary。
- command request、Relay received、Host accepted/rejected 和 terminal result。
- `OutcomeUnknown`，明确表示“不自动重跑”。
- schema version、能力协商、未知事件和不兼容客户端的处理。

语义规范的权威验收物不是某一种语言的类型，而是：版本化 schema、状态不变量、golden traces 和跨实现 conformance tests。

### 6.2 Security Envelope v0

Security Envelope 只有在威胁模型、信任根、设备加入、吊销轮换和无恢复行为确定后才能冻结。它至少覆盖：

- sender、recipient、device identity 和 key version。
- 密文 payload 的类型、语义版本、长度和 chunk 关联。
- 签名覆盖范围、nonce/counter、创建时间、有效期和 replay protection。
- command 的 `session_id`、`turn_id`、`request_id`、action hash 和客户端能力。
- 吊销后的拒绝规则与新 key epoch。
- 协议降级与未知 envelope 版本必须 fail closed。

密码算法和握手模式必须由成熟库提供，并通过独立评审；本架构不预先把候选算法写成已接受决定。

### 6.3 Transport 语义

- Relay 到 Host/Mobile 是至少一次投递。
- 接收方以稳定 message ID 去重密文 frame，以 command `request_id` 去重业务接纳。
- Relay ACK 只表示密文被目标设备持久接收，不表示 Host 已接受命令。
- Push 只表示“可能有新内容”，客户端必须回前台后恢复和校验。
- Presence 和 heartbeat 可以丢失，不进入 durable seq。

## 7. 核心数据流

### 7.1 事件投影与实时同步

1. Adapter 从 OpenCode SSE 或快照观察上游变化。
2. Projector 对上游记录做稳定去重，映射为 Nomad durable event 或 ephemeral delta。
3. Durable event 与新的 upstream cursor、Nomad `seq` 在 Connector 本地事务中提交。
4. Sync client 将事件编码、加密、切块并写入本地有界 outbox。
5. Relay 存储密文并尽力实时投递；Mobile 持久接收后 ACK。
6. Mobile 验证 envelope，按 `seq` 应用 reducer；有 gap 时保持 Reconnecting/Stale。
7. Host 周期性或按需发送 snapshot；Mobile 校验 snapshot digest 后才能进入 Live。

### 7.2 Reply

1. Mobile 生成 `request_id`，签名并发送；UI 显示“发送中/Relay 已收到”。
2. Connector 验证设备、版本、Session、freshness 上下文和 request 是否重复。
3. Connector 持久记录 Host accepted/rejected，再调用固定 OpenCode API。
4. Adapter 观察 `message.accepted` 和后续 durable progress，投影回所有客户端。
5. 重复 request 返回已有结果，不创建第二条上游消息。

Host 离线或客户端 Stale 时，Mobile 只保存本机草稿，不把文本上传为待执行命令。

### 7.3 Stop 与 interrupt-and-send

1. Stop 只在 Online + Live 时可提交，且不离线排队。
2. Connector 去重并请求 OpenCode Stop，进入 `Stopping`。
3. 只有观察到原 turn `Cancelled` 或等价可证明终态后，Connector 才接纳后续消息。
4. 若终态无法确认，不发送新消息，显示明确未知或失败状态。

### 7.4 Permission

1. OpenCode 创建唯一 pending permission；Connector 不创建第二个领域 pending。
2. Adapter 读取原始请求并生成规范化事实、allowability、action hash 和有效期。
3. Mobile 展示 Host 事实；模型说明只能出现在“不可信说明”区域。
4. Allow once 需要本地认证；高风险或未知影响范围不提供 allow。
5. Connector 收到决定后重新读取同一 upstream pending，比较所有绑定字段。
6. 第一个合法决定胜出；版本变化、过期、吊销、断线或不可确认均 fail closed。
7. Adapter 从 OpenCode 事件或快照确认最终结果。无法确认副作用时不得重放，投影为 `OutcomeUnknown` 或明确的 adapter 未知状态。

若 OpenCode 阻断验证不通过，产品永久降级为查看、deny 和 Stop，直到自有 Runtime 迁移门通过。

### 7.5 Diff

1. Session 开始时 Host 记录 Git 与 workspace 基线。
2. Workspace observer 生成文件统计和按文件 chunk 的统一 diff。
3. 未跟踪、删除、重命名、二进制、生成文件和超大文件显式分类。
4. 检测到外部修改时设置不可归因标记，不能写成 Agent 产出。
5. 基准变化使旧 diff 失效；Mobile 不允许继续把旧内容显示为当前。

### 7.6 恢复

1. 客户端以 `last_applied_seq`、snapshot ID/digest 和能力版本发起 resume。
2. 可补齐时返回缺失 durable events；超过 compaction/retention boundary 时返回新 snapshot。
3. 客户端丢弃重复事件，拒绝无法解释的 gap 和版本。
4. reducer 与 snapshot 校验一致后进入 Live。
5. Relay 不可达时本地 Agent 继续；Connector 只保留有界 buffer，超限时进入可诊断降级并要求 snapshot 恢复。

## 8. 数据与一致性模型

### 8.1 权威数据归属

| 数据 | 权威 owner | 副本 |
| --- | --- | --- |
| OpenCode Session/Turn/Permission | OpenCode | Connector/Mobile 投影 |
| Nomad event seq 与 adapter mapping | Connector | Relay 密文、Mobile 投影 |
| 设备注册与吊销状态 | Relay directory + 已授权设备的签名视图 | Host/Mobile cache |
| 内容密钥 | 已授权终端设备 | Relay 无密钥 |
| 命令是否被 Host 接纳 | Connector command journal | Mobile 投影 |
| 命令最终结果 | OpenCode 事实经 Connector 投影 | Mobile 投影 |
| Mobile UI 状态 | Mobile reducer | 可从 snapshot/events 重建 |

### 8.2 一致性不变量

- 同一 Session 的 durable `seq` 严格递增，事件 ID 稳定。
- 未知 gap 存在时客户端不得显示 Live。
- 同一 `request_id` 最多被 Host 接纳一次。
- Relay ACK 不能被展示为 Host accepted。
- Permission 从同一 upstream pending 只进入一个终态。
- 已吊销设备不能提交新命令，也不能读取新 key epoch。
- ephemeral delta 丢失不改变最终 durable message。
- 结果不明的外部副作用不能自动重跑。
- Connector 投影最终与 OpenCode 快照收敛；Runtime Alpha 才要求 event 与 projection 同事务提交。

## 9. 存储设计原则

### 9.1 Connector 本地存储

建议使用嵌入式事务数据库保存 projection metadata、command journal、outbox 和 snapshot metadata。正式引擎由实现 ADR 决定，但必须满足：

- 单进程 writer。
- schema migration 可前进、可检测不兼容版本。
- cursor、event mapping 和 outbox 原子提交，避免“已推进游标但事件未发送”。
- command accepted 与去重键原子提交。
- 内容 buffer 有容量和时间上限，支持用户删除。

### 9.2 Relay PostgreSQL

逻辑表至少覆盖 accounts、devices、device epochs、pairing sessions、mailbox frames、frame ACK、push outbox、revocations 和安全 audit metadata。

所有表必须有明确的数据分类、TTL、删除路径和禁止日志字段。密文 frame 按 opaque session ID、目标 device、message ID、chunk index 和过期时间索引；Relay 不按内容类型建索引。

### 9.3 Mobile 本地存储

- 系统安全存储只保存私钥或数据库密钥引用。
- timeline/diff cache 静态加密，退出登录、设备吊销和卸载时删除。
- 未发送文本只保留为本机草稿。
- UI 派生状态不作为不可重建的事实。

## 10. 安全架构

### 10.1 必须在代码前冻结的内容

- 信任根和账户恢复边界。
- 首台 Host、首台 Mobile 和新增设备的授权者。
- 配对握手、双方确认和 comparison code 的语义。
- 吊销传播、key epoch 轮换和历史密文访问策略。
- 全部可信设备丢失后的明确行为。
- Mobile 远程 allowlist 和风险分类规则。

### 10.2 纵深防御

- OpenCode API 只绑定 loopback，Connector 不提供透明公网代理。
- WSS 传输加密不能替代应用层 E2EE。
- Relay 对 frame 大小、速率、目标和 TTL 做内容无关限制。
- 签名决定必须包含完整绑定上下文，Host 使用当前事实复核。
- Mobile 的 allow once 使用本地认证；App 切换器隐藏敏感内容。
- 日志、trace、crash 和 Push 使用字段 allowlist，不依赖事后正则脱敏。
- 发布产物签名并生成 SBOM；依赖与许可证持续扫描。

## 11. 可观测性与隐私

统一关联字段只允许使用化名化的 `trace_id`、opaque account/device/session ID、request ID、客户端版本、错误码和时延 bucket。

禁止进入日志、指标标签、trace attribute 或 crash breadcrumb 的内容：

- Prompt、回复、代码、diff、路径和仓库名。
- 命令、工具参数、环境变量和 Git remote。
- 密钥、Token、完整 Push token 和配对秘密。

关键指标按链路拆分：

- Host event observed -> Connector committed。
- Connector encrypted -> Relay accepted。
- Relay delivered -> device ACK。
- Push outbox -> APNs accepted -> App receipt/foreground calibration。
- Mobile command sent -> Relay received -> Host accepted -> terminal result。
- reconnect started -> gap closed -> snapshot verified -> Live。

## 12. 部署与发布

### 12.1 Alpha 拓扑

- 一个单区域 Relay 部署单元，可运行多个无状态 gateway 实例。
- 一个 PostgreSQL 主库承担 metadata、mailbox 和 outbox。
- retention/push worker 可作为同一制品的独立进程角色。
- Connector 作为签名 macOS 制品安装，OpenCode 端口仅 loopback。
- iOS 通过测试分发，版本与协议能力由服务端和 Host 同时校验。

### 12.2 兼容与回滚

- 语义版本、envelope 版本、Connector、Relay、Mobile、OpenCode 固定版本分别记录。
- 未知安全命令或 envelope 版本 fail closed；只读事件可按兼容策略降级。
- 数据迁移前保留上一稳定版本可读取的恢复路径。
- feature flag 只能缩小高风险能力，不能绕过 Host 校验。

## 13. 质量策略

| 层级 | 测试类型 | 重点 |
| --- | --- | --- |
| Schema | golden vectors、compatibility、unknown fields | 跨语言一致 |
| State machine | model/property tests | seq、gap、command、permission 竞争 |
| Adapter | 固定 OpenCode fixture、record/replay、snapshot parity | 上游漂移和 fail closed |
| Relay | mailbox/ACK/TTL/重复投递测试 | 不解释内容，短期可靠传输 |
| Mobile | reducer、lifecycle、large list/diff、accessibility | Stale/Live 正确、不卡顿 |
| Security | replay、revocation、action mutation、malicious payload | 0 跨会话或错误绑定 |
| Resilience | packet loss、reorder、restart、disk full、kill | 最终收敛、无未知 gap |
| Performance | fixed fixture、p50/p95/p99、RSS、I/O、soak | 满足 PRD 门槛 |
| End-to-end | disposable repo、真实固定 OpenCode binary | 用户闭环与可诊断性 |

## 14. 建议仓库边界

以下只是未来实现的目录所有权建议，不代表本轮创建代码骨架：

```text
contracts/                 # 语言中立 schema、test vectors、golden traces
connector/                 # macOS Host Connector 与 CLI
relay/                     # Relay 模块化单体与 worker
mobile/                    # iOS 或 RN 客户端，技术 spike 后冻结
runtime-spike/             # 与产品路径隔离的 Rust Session/Event 实验
testkit/                   # fake OpenCode、fault proxy、conformance/e2e harness
docs/technical/adr/        # 架构决策记录
docs/technical/tasks/      # 原子任务卡与完成留痕
```

共享目录由明确 owner 管理。业务 agent 不应顺手修改 contract；需要变更时先新增兼容测试和 ADR，再由 contract owner 合入。

## 15. 关键架构决策

| ID | 决策 | 状态 | 依据/门槛 |
| --- | --- | --- | --- |
| A-001 | Validation Companion 以 OpenCode 为唯一 Session writer | Accepted | 产品 D-002、D-010 |
| A-002 | 采用语义、编码、安全信封、传输四层协议 | Accepted | 防止信任模型污染产品语义 |
| A-003 | 若 D-005 安全门通过，Relay 采用 opaque mailbox，不运行 Session reducer | Conditional | local-first 与 E2EE；随 D-005 接受或停止 |
| A-004 | Alpha Relay 采用模块化单体 + PostgreSQL | Proposed | 先验证闭环；压测证明需要后再拆分 |
| A-005 | Mobile 使用 snapshot + durable event reducer | Accepted | 弱网恢复与多端一致性 |
| A-006 | Approval/Stop 不离线排队 | Accepted | PRD 明确边界 |
| A-007 | OpenCode adapter 是反腐层，客户端不依赖上游 schema | Accepted | 固定版本验证与未来替换 |
| A-008 | Security Envelope 在信任与密钥模型后冻结 | Accepted | 产品 D-005 尚为 Proposed |
| A-009 | Mobile 技术栈由专项 spike 决定 | Proposed | PRD 待决问题 |
| A-010 | Rust Runtime 与 Companion 解耦并按迁移门启用 | Accepted | 产品 D-006、D-014 |

## 16. 待决问题与最晚决策点

| 问题 | 最晚决策点 | 阻塞内容 |
| --- | --- | --- |
| 信任根、设备加入、吊销轮换和无恢复行为 | Security Envelope 实现前 | 配对、E2EE、外部真实仓库 |
| Private Alpha 的账户认证与恢复边界 | Security Envelope 实现前 | Mobile login、设备 bootstrap、账户删除 |
| Mobile 原生或 React Native | Mobile spike 结束 | Mobile 正式目录和构建链 |
| OpenCode permission 是否满足原子竞争与 fail closed | Dual Spike 结束 | 手机 allow once |
| Connector 的实现语言和本地数据库 | Connector spike 结束 | 正式安装包和长期维护 |
| Security Envelope 的成熟协议/库 | 独立安全评审前 | 跨网内容和命令 |
| 远程 allowlist | Private Alpha 前 | Approval allow once |
| Rust 是否进入默认产品路径 | Native Runtime Spike 结束 | Runtime Alpha |
| Relay 是否需要额外缓存/对象存储 | 压测或多实例前 | 扩容拓扑 |

## 17. 架构完成定义

本架构只有在以下证据存在时才算可进入 Private Alpha，而不是以组件“开发完成”判断：

- Session Semantics v0、Security Envelope v0 和 adapter contract 均有版本、golden traces 和 owner。
- 固定 OpenCode 版本能证明唯一 pending permission、原子竞争和 fail closed；否则产品已按约束降级。
- 弱网、重启、重复、乱序、吊销、action mutation 和过期测试通过。
- Mobile 在 gap 校验完成前不会显示 Live，也不会提交安全命令。
- Relay 数据库、日志、Push 和诊断样本不含内容。
- 同一 request 没有重复 Host 接纳，未知副作用没有自动重跑。
- 发布门要求的恢复、安全、性能和真实使用证据全部归档。

## 18. PRD 到实施追踪矩阵

| PRD 能力 | 架构落点 | 主要任务 | 发布证据 |
| --- | --- | --- | --- |
| HC-01 固定 OpenCode 版本 | Supervisor + adapter 反腐层 | HC-001、HC-003 | QA-002、QA-005 |
| HC-02 状态转换 | Semantic projector | CON-001..005、HC-004..005 | QA-001、QA-002 |
| HC-03 loopback | Host 信任边界 | HC-003 | QA-005、安全扫描 |
| HC-04 命令去重 | Command arbiter + journal | CON-003、HC-007..010、HC-015 | QA-003、QA-006 |
| HC-05 workspace diff | Workspace observer | HC-011 | MB-010、QA-005 |
| HC-06 sleep | Host lifecycle | HC-014 | QA-005 |
| HC-07 bounded projection | 有界 payload/outbox/mailbox | CON-002、HC-006、RL-003..004 | QA-003、性能报告 |
| HC-08 诊断升级 | Diagnostics + release | HC-013、HC-016、OPS-002 | QA-004..006 |
| SP-01 seq/version | Session Semantics | CON-001..002 | QA-001 |
| SP-02 snapshot/recovery | Recovery protocol | CON-004、HC-005、MB-003..004 | QA-003、QA-006 |
| SP-03 command dedup | Command lifecycle | CON-003、HC-007..010 | QA-003、QA-006 |
| SP-04 E2EE | Conditional Security Envelope | SEC-001..003、HC-006、MB-004 | QA-004、独立安全评审 |
| SP-05 device revoke | Device lifecycle | SEC-002、HC-012、RL-006、MB-005 | SEC-005、QA-006 |
| SP-06 presence 分离 | 协议分层 | CON-002、MB-003 | QA-001 |
| SP-07 version negotiation | Semantics + Envelope version | CON-001、SEC-003、RL-002 | QA-001、QA-004 |
| MB-01 Home | Mobile presentation | MB-006 | QA-005 |
| MB-02 Timeline | Mobile reducer/presentation | MB-003、MB-007 | 性能与设备测试 |
| MB-03 Approval | Approval verifier/card | HC-009..010、HC-015、SEC-004、MB-011 | SEC-005、QA-006 |
| MB-04 Diff | Diff projection/viewer | HC-011、MB-010 | 性能与 QA-005 |
| MB-05 Queue/interrupt/Stop | Command client/arbiter | HC-007..008、MB-008..009 | QA-003、QA-005 |
| MB-06 Push | Push outbox + lifecycle calibration | RL-007、MB-012 | QA-004、QA-006 |
| MB-07 App lock | Secure identity | MB-002、MB-013 | 设备安全测试 |
| MB-08 Voice draft P1 | 当前架构保留扩展点 | 后续独立任务 | 不属于 P0 发布门 |

任何新增 P0 需求在进入实现前必须补充本矩阵与对应原子任务；不能只在某个组件中隐式实现。
