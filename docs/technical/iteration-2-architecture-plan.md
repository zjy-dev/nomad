# Controlled Pilot v0.2 技术架构与开发拆分

| 字段 | 内容 |
| --- | --- |
| 状态 | Engineering milestone complete; external Pilot blocked |
| 日期 | 2026-08-18 |
| 产品输入 | `docs/product/iteration-2-prd.md`、`product-backlog.md` |
| 本轮目标 | 交付固定 OpenCode 接口到移动产品界面的首个真实进程纵向切片 |
| 非目标 | 生产 E2EE、APNs、原生 iOS、真实仓库、移动 allow_once、自有 Runtime |

## 1. 架构决定

### A-201：冻结 Session Semantics v0

本轮不修改 `contracts/schemas/` 和 golden traces。Host 将 OpenCode HTTP/SSE 响应适配为现有 Snapshot/Event/Command 语义；消费方不能添加私有协议状态。

### A-202：固定 OpenCode 兼容接口 + Fake OpenCode

Host 只连接 `http://127.0.0.1:4096`，校验固定版本 `1.18.16`。实现：

- preflight/version check；
- Session snapshot 与 durable event 拉取；
- reply、deny、Stop command；
- 未知事件 fail closed；
- `allow_once` 始终拒绝。

项目内 fake OpenCode 实现同一网络接口，用于自动化和可丢弃 Pilot 场景。它是接口替身，不是 fixture 直读捷径。

### A-203：移动端采用 API 边界，不再直接耦合 MockHost

Mobile 引入 `SessionClient` 接口；默认 Pilot client 从 Host/Relay 兼容 API 获取 session，开发和 golden trace 由 mock 实现注入。产品 UI 默认加载 Pilot Session，不展示 trace loader；开发场景仍可通过显式 query 参数进入 trace lab。

### A-204：权威 Changes 无数据即空态

Diff 数据包含来源、基线和文件 hunks。Mobile 禁止在 `diffFileCount>0` 时回退到示例文件。只有 Host 提供的权威 diff 才进入 Changes。

### A-205：Relay 重启恢复以持久 mailbox 验证

Pilot Relay 使用 SQLite test bridge store 的持久化能力。恢复测试必须覆盖：未 ACK event 在重启后仍可补发、已 ACK event 不重现、相同 message ID 不产生第二条记录。

### A-206：Pilot 安全说明是硬门

外部候选接入前必须有 Pilot Security Note，覆盖 loopback Host、测试 Relay token、TLS 部署要求、数据分类、保留清理、设备解绑、停止条件。它不替代 D-005 或 Security Envelope v0。

## 2. 组件边界

```text
Fake / Fixed OpenCode API :4096
        | HTTP + SSE-compatible events
        v
Rust Host Adapter + command journal
        | Session Semantics v0 / command result
        v
Go Pilot Relay (persistent mailbox, TEST-ONLY boundary)
        | poll / ack / resume
        v
Mobile Web SessionClient
        |
        +-- Home: needs attention / running / recent
        +-- Activity: user-language progress
        +-- Action: Host facts, deny / Stop only
        +-- Changes: authoritative diff or empty state
```

## 3. 并行开发包

| Lane | 产品需求 | 独占文件 | 交付 |
| --- | --- | --- | --- |
| Host | PRD-203、205、206、207、208、209 | `connector/` 新模块与测试，`testkit/fake-opencode/` | 网络 adapter、preflight、真实 command、fake server、证据 |
| Mobile | PRD-210、211、212、213、214 | `mobile-reference/src/`、browser smoke | 产品 IA、API boundary、真实/空 diff、可用性语义 |
| Relay | PRD-204、215、218 | `relay/`、独立恢复测试 | 配对过期/消费、重启恢复、channel cleanup |
| Quality/Security | PRD-216、217、225 | `testkit/pilot/`、`docs/technical/security/` | doctor、内容安全遥测、Pilot Security Note、集成验收 |

禁止并行修改：`contracts/`、产品文档、其他 lane 独占目录、用户已有 `last-transcript.json`。共享接口缺口先写到各自报告，由技术负责人合流。

## 4. 合流门

1. 各 lane 自测通过并留下 completion report。
2. Rust、Go、TypeScript、Python 全量测试通过。
3. Fake OpenCode → Host → Relay → Mobile/API 的真实进程用例通过。
4. 浏览器在 390×844 下默认进入产品态，不出现 golden trace loader。
5. Changes 没有权威数据时不出现示例文件。
6. Stale/Offline 阻止命令；RelayReceived 不冒充 HostAccepted。
7. `allow_once` 在 UI 缺席、Host 拒绝、测试覆盖。
8. 独立 PM 按 PRD 验收；P0/P1 反馈完成返工或有书面降级决定。

## 5. 风险与降级

| 风险 | 降级 |
| --- | --- |
| 固定 OpenCode API 与当前假设不同 | 保持 adapter trait 与 capture 工具，使用 fake OpenCode 完成接口验证，不宣称真实版本认证 |
| deny 无法绑定真实 upstream pending | Action 页只显示 facts + Stop；保持 HC-009 No-Go |
| 移动 Web 无法证明后台行为 | 只计前台 Pilot；不外推 Push/后台结论 |
| Relay 尚无生产身份/E2EE | 只用于可丢弃数据；安全说明和部署限制为硬门 |
| 并行 lane 出现 contract 分歧 | contract owner 统一修复，不让消费端复制字段 |
