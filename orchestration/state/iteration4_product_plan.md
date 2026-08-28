# Iteration 4 Product Plan

状态：Phase 4 Product Manager 计划。本文只定义产品分级和执行门，不改变代码、证据、发布或外部信任状态。

## 1. 当前判断

commit 4e4ac68 已推送。native test-only launch/transport、audit GET/SSE、一次 reconnect 已独立审计通过；default production supervisor 保持 zero-spawn。它们是可复用的工程 mechanics，不是用户产品 readiness。当前进度是 blocked_at_external_real_product_gate。

仍缺少：allowlisted temporary Provider credential、同一真实 run 的 lifecycle evidence、Developer ID Host、SSHSIG trust/KRL、protected CAS/publication，以及真实四跳 Host 到 Mobile 证据。因此不得用 synthetic trace、Python/测试结果或 native test-only marker 替代这些门。

## 2. Agent-neutral core 与 OpenCode adapter

### Agent-neutral core

Core 是 Nomad 自有且不依赖具体 agent 的版本化产品合同：Session、Turn、Event、Snapshot、Command、Result；单调 seq、snapshot digest、gap/reconnect、OutcomeUnknown；Host command arbiter、request 去重、accepted/rejected/terminal result；permission pending fact、action hash、参数/cwd/版本/有效期校验；workspace baseline/diff 与不可归因标记；Security Envelope、设备吊销、E2EE frame、Relay ACK 和 Mobile reducer。

Core 不知道 OpenCode 私有 event、V1/V2 route、Provider credential、上游数据库或模型。验收物是版本化 schema、状态不变量、golden traces 和跨实现 conformance tests。

### OpenCode adapter

Adapter 是固定版本 OpenCode 的兼容层：读取 HTTP/SSE、snapshot、question、permission、diff；将上游事实映射为 core 语义；维护稳定 upstream cursor/id 映射；只调用经过 live shape/provenance 验证的命令。它不暴露私有 schema、不成为第二个 Session writer、不持有 Provider credential、不把 mock 结果升级为 authority。OpenCode 是 Validation Companion 阶段唯一 Session 事实源；未来 Runtime Alpha 是新的 Session owner，必须与 OpenCode 分离迁移。

## 3. 产品分级

### Product Alpha：Validation Companion / local-first preview

用户价值：开发者在本机和受限客户端看到结构化 Session 进度、变化及明确的不可用/未知状态；真实门打开后可安全完成受限 reply、deny、Stop。它不是远程终端或云端续跑。

In scope：Apple Silicon macOS Host Connector、固定 OpenCode adapter、loopback observation；Session contract、Mobile reducer、snapshot/gap/reconnect、read-only diff、受限 approval/deny/Stop UI；单区域 opaque Relay mailbox、ACK/TTL/Push、配对/吊销最小闭环；diagnostics、privacy-safe metrics、bounded outbox、故障注入。

Out of scope：云端续跑、托管 workspace、PTY/SSH 默认协议、任意 shell、手机永久权限、离线执行、Relay 解密/搜索/审批、自有 Runtime、第二 Host/移动平台、多 Host 协作，以及真实 evidence/trust 完成前的 Product V2。

DoD：core schema/golden traces/conformance 冻结；Host/Relay/Mobile 测试闭环覆盖 ACK、重连、去重、吊销、删除；adapter shape、snapshot/event mapping、reply/deny/Stop 独立审计；无真实证据时 product path fail closed、supervisor zero-spawn；安全、隐私、性能、崩溃恢复和诊断验收通过。真实证据只能来自可独立复核的 conformance、native mechanics transcript、adapter audit 和受控四跳验证。

Owner：Core/Host、adapter、Relay、Mobile owners；PM 负责 scope 和用户验收；Security DRI 负责 envelope、配对、吊销。Go 条件是仅开放 read-only/明确受限动作；raw upstream facts 越界、Relay 可解释正文、Mobile 离线执行、未知 gap 显示 Live 或 test marker 解锁生产能力时 No-Go。

### Controlled Pilot：小规模真实用户闭环

用户价值：少量明确同意的内部/受控用户，以真实 Provider-backed OpenCode Session 完成可观测、可恢复、可审计的 Host 到 Relay 到 Gateway 到 Mobile 闭环。

In scope：单区域、allowlisted 用户、单 Host/单 Mobile 配对、固定 OpenCode；真实 Session、diff、question/reply、permission deny、Stop、断线重连；受控 workspace、temporary credential、incident runbook、删除和成本/延迟监控。Out of scope：任意用户开放、自有 Runtime、高风险工具、复杂 allow_once、跨区 failover、无人工批准的扩容、远程创建任务和云端正文存储。

DoD：一真实 run 产出同一 authority 绑定的 staged certificate、shape manifest、evidence manifest；A3/A4.2/B0.1 独立 exact VERIFIED；外部 reviewer 审核 digest、source/provenance、credential scope、content-free、cleanup；Developer ID Host、SSHSIG trust/KRL、protected CAS 已外部验证；至少一条真实四跳 e2e 含重连、去重、拒绝和故障恢复；用户、成本、incident owner 和 kill switch 明确。

Owner：Pilot PM/Engineering DRI；Host/Release、Security、Platform/Relay、Support/Operations 分别负责发布信任、安全、四跳和 incident。外部依赖为 temporary credential、Provider policy、Developer ID/notarization、SSHSIG signer/KRL/trust、protected CAS、受控设备/APNs/Relay。任一外部门缺失、证据来自 fixture/mock/synthetic、出现重复副作用/正文泄露/未知 Stop时 No-Go。

### Beta / GA

用户价值：扩展为可依赖的跨端 Session 产品，在弱网、设备变更和故障下仍保持一致、可解释、可删除的状态，并保持本机安全裁决。

Beta In scope：扩大用户/设备矩阵、版本协商、有限容量/跨区验证、telemetry、incident response。GA In scope：支持版本策略、SLO/SLA、容量/成本、备份恢复、删除/吊销审计、客服和安全响应。Runtime Alpha 只有在独立迁移门通过后评估。

Out of scope：GA 前云端续跑、任意 shell、永久手机权限、多 Host、第二 Host OS；Runtime Alpha 不得绕过 core/security envelope 或与 OpenCode 共写 Session。

DoD：Beta 通过真实 soak、crash/restart、弱网/gap、吊销/轮换、升级兼容、容量/成本门；GA 有连续真实数据支撑可用性、重连收敛、重复率、未知结果率、删除时延、密文保留和安全响应 SLO；独立安全评审覆盖 threat model、签名/nonce/replay、密钥轮换、CAS、Host identity、Provider/Relay 边界；每次发布绑定 immutable release、source/provenance、approval 和 rollback。真实证据包括 cohort metrics、soak/crash、独立安全报告、升级/回滚、容量、删除/吊销和 incident 演练。

Owner：Release/Platform/SRE、Security、Product/Support、core/adapter/Relay/Mobile owners。外部依赖为 Developer ID/notarization、SSHSIG trust、protected CAS/release service、Provider、APNs、监控值班、隐私法务。缺连续真实数据、可执行 rollback、稳定 trust/CAS 或可证明删除/吊销时 No-Go。

## 4. 五个可执行 work packages

### WP1：Core contract 与跨端 conformance
Owner：Core protocol + Mobile reducer。交付版本化 Session Semantics/Security Envelope 输入、golden traces、snapshot/gap/OutcomeUnknown、命令状态机和 conformance。DoD 是 schema/invariants 评审通过、Host/Mobile/Relay 共用 vectors、未知字段/gap/replay/duplicate request fail closed。依赖 Security、Mobile/Relay owners；无一致性和安全边界证据不进 Pilot。

### WP2：Controlled real evidence gate
Owner：M2 evidence/Pilot operator + Security reviewer。按 operator runbook 执行真实 temporary credential run，产出 staged triple；A3/A4.2/B0.1 exact VERIFIED，完成 source/provenance/content-free/cleanup audit。依赖 allowlisted credential、locked OpenCode、Developer ID Host、SSHSIG trust/KRL、protected CAS；任一外部门缺失即保持 blocked_at_external_real_product_gate。

### WP3：Alpha four-hop product slice
Owner：Host/Relay/Gateway/Mobile leads。交付单区域受控四跳 slice：read/reply/deny/Stop/diff/reconnect/ACK/去重/删除/诊断，保持 Host 最终裁决、Relay opaque。DoD 是真实或获批受控 slice、端到端审计、故障注入、用户任务完成、无重复副作用/正文泄露。依赖 WP1/WP2、配对、APNs/Relay、用户支持；任何一跳只有 synthetic proof即 No-Go。

当前批准执行的只是 WP3 的 `localhost-only read-only Alpha slice`：Host projector、Relay、Gateway 和默认 Mobile UI 的真实只读链路。它不包含 pairing、revocation、reply、deny、Stop 或其他写能力；这些仍属于后续完整 Alpha 或 Pilot 前置门，不能由本轮本地证据解锁。

### WP4：Trust、release 与 native supervisor production gate
Owner：Release/Host + Security DRI。交付 Developer ID Host、SSHSIG approval/KRL/trust、protected CAS immutable publication、native supervisor fixed-input authority；门未齐时 default zero-spawn。DoD 是 opened-file identity、CAS lineage、签名/吊销/回滚、native blocker 和 zero-spawn report。Python marker、env、caller digest、test authority不能打开 production child。

### WP5：Beta/GA reliability 与 operations
Owner：Platform/SRE + Product/Support + Security。交付版本兼容矩阵、SLO/SLI、soak/crash/restart/weak-network、容量/成本、删除/吊销、incident/rollback、隐私审查。DoD 是真实 cohort 数据、安全报告、发布/回滚/删除/吊销演练和值班手册。依赖 WP1-WP4、Provider/APNs/release service、隐私法务；无连续真实数据和 rollback 不进 GA。

## 5. 当前 go/no-go

- Product Alpha：CONDITIONAL GO。可继续交付 agent-neutral core、固定 adapter 的验证预览和产品 contract；不开放真实 Pilot 动作，不改变 default supervisor zero-spawn。
- 当前本地只读 Alpha 子切片：GO。只允许 `Host projector -> Relay -> Gateway -> Mobile` 的 loopback-only、默认非 mock、无命令闭环；不得据此宣称完整 Product Alpha、Controlled Pilot 或 production ready。
- Controlled Pilot：NO-GO。缺 allowlisted Provider credential、真实 lifecycle evidence、Developer ID Host、SSHSIG trust、protected CAS。
- Beta：NO-GO。须先完成 WP2/WP3/WP4 并取得真实 cohort、稳定性和安全证据。
- GA：NO-GO。Beta SLO、独立安全审计、运维/发布/回滚和外部信任依赖未满足。

本计划不新增 synthetic-only 工作；native test-only launch/transport/audit GET/SSE/reconnect 只作为后续真实门的工程基础。
