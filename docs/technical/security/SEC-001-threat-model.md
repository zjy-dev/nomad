# SEC-001 系统威胁模型

| 字段 | 内容 |
| --- | --- |
| 关联任务 | SEC-001 |
| 关联决策 | D-005（Proposed，本文件不改变其状态） |
| 关联架构 | `docs/technical/architecture.md` |
| 关联 PRD | 第 10.3、13 节 |
| 作者 | Security owner |
| 状态 | Draft |
| 日期 | 2026-08-17 |

本文件在选择密码方案之前冻结资产、参与方、信任边界和攻击面。密码算法和协议库的选择不属于本任务；见后续 SEC-003。

## 1. 范围与不在范围

**在范围：**

- Host Connector、Relay、Mobile Companion、APNs、模型 Provider、OpenCode loopback 之间的交互。
- 配对、设备生命周期、命令接纳、审批、重放、跨会话审批、日志泄露、供应链、旧客户端、设备丢失、恶意 Relay。
- Validation Companion 阶段的威胁模型；Runtime Alpha 增加的信任边界单独补充。

**不在范围：**

- 直接选择密码算法或把 D-005 改为 Accepted。
- OpenCode 自身内部实现的安全缺陷；Nomad 仅信任其 loopback HTTP/SSE 边界。
- 用户电脑上的其他进程或操作系统内核级攻击，除非它们改变 Nomad 信任边界。
- 手机 App Store 分发链路安全、APNs 自身协议安全（作为外部依赖建模）。
- 密钥恢复设计；Validation Companion 明确不提供恢复。

## 2. 资产清单

| ID | 资产 | 位置 | 性质 | 威胁等级 |
| --- | --- | --- | --- | --- |
| A-01 | Session 持久事件（消息、工具执行、diff、权限记录） | Connector 本地、Relay 密文、Mobile 加密缓存 | 含用户代码、命令、Prompt、工具输出 | Critical |
| A-02 | Session 状态投影与快照 | Connector、Mobile | 结构化业务事实 | High |
| A-03 | 命令 request journal 与去重键 | Connector 本地 | 决定 Host 是否接纳一次副作用 | Critical |
| A-04 | 设备身份密钥（Host 与 Mobile） | macOS Keychain / iOS Keychain+Secure Enclave | 签名与 E2EE 密钥材料 | Critical |
| A-05 | 配对短期凭据与 comparison code | Connector、Mobile 瞬时状态 | 一次性使用 | High |
| A-06 | Relay 账户/设备目录与公钥 | Relay PostgreSQL | 元数据，不含内容 | Medium |
| A-07 | Relay 密文 mailbox | Relay PostgreSQL bytea | 密文，保留 7 天或 ACK | High |
| A-08 | Push token 与 opaque deep-link | Relay、APNs | 路由元数据，不含内容 | Medium |
| A-09 | OpenCode Provider API Key | 用户本地 OpenCode 配置 | Connector 不接触 | Critical |
| A-10 | 工作区 Git 与文件系统 | Host 本地 | 代码与仓库历史 | Critical |
| A-11 | 设备吊销状态与 key epoch | Relay 目录、已授权设备签名视图 | 信任根元数据 | High |
| A-12 | 产品遥测与诊断包 | 用户主动上传 | 默认脱敏，可含元数据 | Low |
| A-13 | Mobile 本地加密 timeline/diff cache | Mobile 本地 | 会话历史副本 | High |
| A-14 | 安全日志与审计元数据 | Connector、Relay、Mobile | 不含正文 | Medium |

## 3. 参与方与信任边界

### 3.1 参与方

| 角色 | 实体 | 动机 | 信任假设 |
| --- | --- | --- | --- |
| Host User | 开发人员 | 跨端推进本机任务 | 拥有 Host 的物理控制权 |
| Host Connector | Nomad 本机守护进程 | 协议投影、命令仲裁、加密出站 | 运行在受信任 macOS 用户空间 |
| Mobile User | 同一用户 | 短时远程推进任务 | 拥有 iPhone 物理控制权 |
| Mobile Companion | iOS App | 接收密文、展示、签名决定 | 私钥进 Secure Enclave；本地生物识别 |
| Secure Relay | Nomad 托管服务 | 密文路由、Push 触发、设备目录 | 不被信任解密内容；仅可信元数据 |
| APNs | Apple Push Notification service | 通用通知投递 | 外部依赖；仅看到 opaque category |
| Model Provider | 用户选定的 LLM 服务 | 推理执行 | 独立数据接收方，E2EE 不覆盖 |
| OpenCode | 本机 loopback Server | Session 事实源、工具执行 | 仅绑定 loopback；不暴露公网 |
| Attacker (Relay Operator) | Relay 运营者或内部威胁 | 可能读取 Relay 数据库 | 不解锁内容；元数据受限 |
| Attacker (Network) | 中间人/ISP/企业网关 | 流量嗅探、降级 | TLS 传输；应用层 E2EE |
| Attacker (Stolen Device) | 获得 Host 或 Mobile 的攻击者 | 获取会话历史、冒充命令 | 物理攻击模型 |
| Attacker (Supply Chain) | 依赖或构建链攻击者 | 植入恶意代码 | 发布产物签名、SBOM、持续扫描 |
| Attacker (Malicious Peer) | 已配对设备被攻陷 | 用合法密钥签发恶意命令 | 吊销传播、绑定上下文复核 |

### 3.2 信任边界图（数据流图）

```text
[Host User]     [Mobile User]
     |                |
     v                v
+----------+     +---------------+
| OpenCode |     | Mobile App    |
| (loopback)|     | (Secure Enclave)
+-----+----+     +-------+-------+
      |                  |
      | HTTP/SSE         | WSS + E2EE
      | loopback only    | signed envelope
      v                  v
+-----+----+     +-------+-------+
| Connector|-----+---> Secure Relay
| (Host)   |  出站WSS   | (opaque mailbox)
+-----+----+     +-------+-------+
      |                  |
      |                  | Push
      |                  v
      |               +------+
      |               | APNs |
      |               +------+
      |
      | 内容由 OpenCode 直接发送
      v
+-------------+
| Model Prov. |
+-------------+
```

**边界定义：**

| 边界 | 描述 | 跨边界内容 |
| --- | --- | --- |
| B-01 OpenCode 边界 | OpenCode 仅监听 `127.0.0.1` | HTTP/SSE 结构化事件；Connector 只读投影 |
| B-02 Connector 出站 | Connector 只发起出站 WSS | E2EE 密文 envelope；不暴露 Host 端口 |
| B-03 Relay 边界 | Relay 只看到密文与有限元数据 | `account_id`、`device_id`、`session_id`、消息大小、时间、TTL、IP |
| B-04 Relay → Mobile | Push 只唤醒，不携带状态 | `push_token`、通用类别、opaque deep-link |
| B-05 Provider 边界 | OpenCode 直接将上下文发往 Provider | 指令、代码片段、工具结果；Nomad 不接触 |
| B-06 Mobile 本地 | Mobile 私钥进 Secure Enclave | 本地持久化密文 timeline/diff cache |
| B-07 设备间配对 | QR + comparison code + 双端确认 | 短期握手材料，一次性消费 |

### 3.3 数据流详细步骤

**路径 1：事件投影与实时同步**

1. OpenCode 产生事件 → Connector 通过 loopback SSE 观察
2. Connector 投影为 Nomad durable event，分配单调 `seq`
3. Connector 本地事务提交事件 + 游标
4. Connector 生成 Security Envelope（含 sender/recipient/session/key version/signature/nonce/expiry）
5. Connector 切块 → 写入本地有界 outbox
6. Connector 出站 WSS → Relay 接收密文 frame
7. Relay 写入 mailbox，尽力投递 → Mobile WSS 接收
8. Mobile 验证 envelope 签名与绑定字段 → 按 `seq` 应用 reducer
9. Mobile 持久接收后 ACK → Relay 保留至 ACK 或 TTL

**路径 2：审批**

1. OpenCode 创建唯一 pending permission
2. Connector 规范化请求，生成 action hash（绑定工具、参数、cwd、可执行文件 hash、脚本 hash、基准、版本）
3. Connector 生成 envelope，包含 action hash、有效期、pending ID
4. Mobile 接收密文，展示 Host 事实；模型说明标为"不可信说明"
5. Mobile 本地认证后签名 allow/deny/stop 决定
6. 密文决定发往 Relay → Relay 转发 → Connector 验证签名与绑定
7. Connector 重新读取同一 upstream pending 的所有绑定字段
8. 字段一致 → 转发决定给 OpenCode；不一致 → fail closed
9. OpenCode 原子解决 pending；Connector 观察结果并投影回所有客户端

**路径 3：配对**

1. `nomad pair` 生成短期 QR（含一次性配对会话 ID、公钥、comparison code）
2. Mobile 扫描 QR，显示 comparison code
3. 双端显示相同 comparison code 与对方设备名
4. 双端确认 → 交换公钥 → 注册到 Relay 设备目录
5. 配对会话一次性消费；过期即失效

**路径 4：命令接纳与去重**

1. Mobile 生成 `request_id`，签名发往 Relay
2. Connector 验证设备、会话、freshness、版本、`request_id` 是否已处理
3. Connector 记录 Host accepted/rejected 到 command journal
4. Connector 调用 OpenCode API；重复 `request_id` 返回已有结果
5. OpenCode 执行；Connector 投影 durable progress 回所有客户端
6. 外部副作用成功但结果未持久化时崩溃 → Turn 进入 `OutcomeUnknown`，不自动重跑

**路径 5：恢复**

1. Mobile 回前台，携带 `last_applied_seq` + snapshot ID/digest 发起 resume
2. Relay 返回缺失 durable events 或新 snapshot
3. Mobile 丢弃重复事件，拒绝无法解释的 gap 和版本
4. Reducer 与 snapshot 校验一致 → 进入 Live

## 4. 攻击者模型

### 4.1 Attacker 概览

| ATT | 角色 | 能力 | 知识 | 目标 |
| --- | --- | --- | --- | --- |
| ATT-A | 远程网络攻击者 | 被动嗅探 TLS 流量；可降级协议 | 可观察 IP、时间、消息大小 | 推断用户行为；尝试降级/中间人 |
| ATT-B | Relay 运营者/内部威胁 | 读取 Relay 数据库、日志、meta 数据；可能修改设备目录 | 知道 `account_id`、`device_id`、`session_id`、消息大小、时间、IP | 批量关联用户；尝试解密密文；伪造元数据 |
| ATT-C | 持有 Mobile 的攻击者 | 获得已配对 iPhone 物理访问；可能绕过本地认证 | 可读取 Secure Enclave 外的 Mobile 存储 | 窃取会话历史；用 Mobile 签发恶意命令 |
| ATT-D | 持有 Host 的攻击者 | 获得已配对 Mac 物理访问；可能运行任意进程 | 理论上可访问 Connector 进程内存 | 窃取密钥或明文会话；拦截/修改出站消息 |
| ATT-E | 恶意 Relay 运营者 | 可能篡改密文、重放、伪造 ACK、篡改设备目录 | 持有 Relay 数据库全部元数据 | 迫使 Mobile/Connector 接受伪造内容 |
| ATT-F | 恶意 Mobile（设备被攻陷/替换） | 使用合法签名密钥签发命令 | 已获得 Mobile 私钥 | 跨会话审批、重放旧命令 |
| ATT-G | 供应链攻击者 | 通过依赖/构建链植入恶意代码 | 能影响发布产物 | 植入后门；窃取密钥 |
| ATT-H | 旧客户端使用者 | 使用过期版本协议 | 知道旧版本漏洞 | 绕过新安全检查 |
| ATT-I | 伪造配对者 | 截获 QR 或诱导用户扫码 | 知道配对协议 | 绑定攻击者设备到用户账户 |

## 5. 威胁分析（STRIDE）

以下威胁使用稳定 ID：`T-XXX`。每个威胁包含：威胁类型、描述、严重度、影响资产、攻击向量、控制措施、Owner、停止条件、残余风险、适用 Kill Switch。

### 5.1 身份认证与会话绑定

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-001 | Spoofing | 旧配对密钥签发新命令 | Critical | A-01, A-04, A-03 | Mobile 私钥被提取或未正确吊销 | 吊销传播：已吊销设备无法读取新 key epoch 或发送新命令；每设备独立密钥；吊销 P95 60 秒内失效 | SEC-002 | 吊销命令在 60 秒内未阻止新命令（吊销后旧 epoch 命令仍被接纳） | 吊销延迟窗口内，若攻击者已持有私钥仍可签发 | K-001 |
| T-002 | Spoofing | 攻击者用旧 key epoch 解密历史密文 | High | A-07, A-01 | 吊销后旧密钥仍可解密旧密文 | key epoch 轮换后新密文用新密钥；旧密文保留可由吊销设备读取 | SEC-002 | 无 | 已吊销设备在旧 epoch 仍可读历史（产品接受：用户放弃恢复） | — |
| T-003 | Spoofing | Mobile 用他人 action hash 为不同请求审批 | Critical | A-03, A-10 | 跨会话审批：旧 approval 用于新上下文 | Approval verifier 绑定 pending ID、参数、cwd、可执行 hash、脚本 hash、基准、版本、有效期；Connector 重新读取同一 upstream pending 复核所有绑定字段 | SEC-004 | 字段复核失败率 > 0（任一绑定字段复核失败即停止，不只是 `request_id` 去重） | 极端时序竞争 | K-004 |
| T-004 | Spoofing | 恶意 Relay 篡改设备公钥绑定 | Critical | A-04, A-06 | Relay 运营者修改设备目录 | 公钥变更需新的配对握手；已授权设备签名视图不能被 Relay 单方覆盖 | SEC-002 | 检测到未经新配对握手的公钥变更（设备目录公钥版本与本地信任根不一致） | Relay 运营者攻击成本高 | K-001 |
| T-005 | Spoofing | 旧 Mobile 版本绕过 envelope 验证 | High | A-01, A-13 | 使用旧版本协议 | 未知安全 envelope 版本 fail closed；版本协商在安全层 | SEC-003 | 未知 envelope 版本被成功验签并接纳 | 用户强制升级风险 | K-007 |

### 5.2 完整性

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-010 | Tampering | 攻击者篡改 Security Envelope 字段（sender/recipient/session/turn/request/action/expiry） | Critical | A-01, A-03 | 中间人、恶意 Relay | 签名覆盖范围包含全部绑定字段；篡改任一字段均验签失败 | SEC-003 | 任何字段篡改被接受（验签失败仍通过） | 密码学成功破解（极低概率） | K-001 |
| T-011 | Tampering | Relay 篡改密文帧 | Critical | A-01 | 恶意 Relay | 每帧独立完整性保护；Relay 不具备解密或修改能力 | SEC-003 | 任何密文帧被接受（完整性校验失败仍通过） | 同上 | K-001 |
| T-012 | Tampering | 已吊销 Mobile 签发命令 | Critical | A-03, A-10 | 设备被攻陷未吊销 | 吊销传播 + key epoch + envelope 签名校验；已吊销设备无法发送新 epoch | SEC-002 | 已吊销设备成功发送并被接纳新 epoch 命令 | 吊销延迟窗口 | K-001 |
| T-013 | Tampering | Mobile 在断线期间篡改本地 timeline cache | High | A-13 | 设备被物理访问 | 本地 timeline 加密；退出登录/吊销/卸载时清除；展示的 diff 必须能与 Host 快照校验 | MB-002/MB-003/MB-004/MB-013 | 无 | 用户主动备份恢复时历史可能泄露 | — |
| T-014 | Tampering | 攻击者篡改 OpenCode loopback 响应 | High | A-01, A-10 | 本机恶意进程 | OpenCode 仅绑定 loopback；Connector 验证上游游标和事件 ID 稳定映射；不得反向写入 OpenCode | HC-003 | 无 | 本机 root 权限攻击者仍可影响 | K-002 |

### 5.3 机密性

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-020 | Disclosure | Relay 数据库泄露暴露会话内容 | Critical | A-01, A-07 | 数据库被盗/运营者内部访问 | 应用层 E2EE：Relay 只保存密文；不持有密钥；密文采用有界 frame | SEC-003 | 密文被解密（Relay 数据库出现明文内容） | 元数据泄露（IP、时间、消息大小、账户 ID） | K-003/K-005 |
| T-021 | Disclosure | Relay 日志/trace 泄露内容 | High | A-01, A-14 | 日志收集系统被攻破 | 日志字段 allowlist：仅允许化名化 ID、版本、错误码、时延 bucket；禁止 Prompt/代码/路径/命令/工具输出 | RL-001/OPS-001/OPS-004 | 任何内容字段进入日志（allowlist 外字段出现） | 元数据关联（见 R-001） | K-003 |
| T-022 | Disclosure | Push payload 泄露内容 | High | A-01, A-08 | APNs 被截获/日志 | Push 只发送通用通知类别与 opaque deep-link；不包含源码/路径/命令/Prompt/diff | MB-012/RL-007 | Push payload 出现内容字段（源码/路径/命令/Prompt/diff） | APNs 提供的设备标识符 | K-006 |
| T-023 | Disclosure | Mobile timeline/diff cache 泄露 | High | A-13 | 设备被攻陷 | 本地加密存储；App 切换器隐藏内容；后台自动锁定；卸载/吊销时清除 | MB-002/MB-013 | 无 | Secure Enclave 旁路攻击（极低概率） | — |
| T-024 | Disclosure | Connector 本地存储泄露 | High | A-01, A-03 | 本机进程读取 | Connector 持久化仅包含投影元数据、命令日志、设备元数据、密钥引用和安全日志；不保存 OpenCode 原始 Session 正文 | HC-002/HC-005 | 无 | 用户主动导出 | — |
| T-025 | Disclosure | 诊断包包含敏感字段 | Medium | A-12 | 用户主动上传 | 诊断包由用户主动生成；上传前可预览；敏感字段默认脱敏 | HC-013 | 无 | 用户手动打开敏感字段 | — |
| T-026 | Disclosure | App 切换器/锁屏预览泄露内容 | Medium | A-13 | iOS 系统截图 | App 切换器隐藏敏感内容；后台一段时间后自动锁定；锁屏无敏感信息 | MB-002/MB-013 | 无 | 合法截图（用户主动） | — |
| T-027 | Disclosure | OpenCode Provider API Key 泄露 | Critical | A-09 | Connector 读取 | Connector 不读取或保存 Provider Key；Key 留在 OpenCode 本地配置 | HC-003 | 无 | OpenCode 自身泄露 | — |

### 5.4 拒绝服务

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-030 | DoS | Relay 被大量密文帧淹没 | High | A-07, A-01 | 速率限制外的恶意发送 | 每账户/设备速率限制；帧大小限制；TTL 限制；内容无关限流 | RL-002/RL-004 | 限流失败（合法流量持续被误限或恶意流量突破限流阈值：单设备 60s 内 > 1000 帧） | 合法突发流量被误限 | — |
| T-031 | DoS | 恶意 Relay 重放大量过期/已处理帧 | High | A-01, A-03 | 重放攻击 | 每帧 nonce/counter + 有效期 + 签名校验；过期帧 fail closed | SEC-003 | 无 | 极小概率的 nonce 碰撞 | — |
| T-032 | DoS | 大量 push 唤醒导致移动端资源耗尽 | Medium | A-08 | 恶意 Relay 滥用 Push | 每账户 Push 速率限制；Push 只唤醒，不携带内容 | RL-007 | 无 | iOS 系统级通知限制 | — |
| T-033 | DoS | 大 payload 撑爆 Relay mailbox | Medium | A-07 | 超大事件 | 有界 frame 切块；每块独立编号；单 Session 总量上限 | HC-006 | 无 | 合法大 diff 被截断 | — |
| T-034 | DoS | OpenCode loopback 被大量请求淹没 | High | A-01 | 本机进程 | Connector 不暴露公网；loopback only；速率限制 | HC-003 | 无 | 本机资源限制 | — |

### 5.5 重放与命令语义

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-040 | Repudiation | 重放旧 reply/Stop/approval 命令 | Critical | A-03, A-10 | 时间窗口内重放 | 每命令 `request_id` + 签名 + 有效期；Connector command journal 去重；重复 request 返回已有结果 | CON-003 | 重复 request 产生二次接纳（同一 `request_id` 在 journal 中被接纳两次） | 同一 request_id 首次接纳后结果丢失 | K-004 |
| T-041 | Repudiation | 旧 approval 跨会话使用 | Critical | A-03, A-10 | 跨会话审批 | Approval 绑定 `session_id`、`turn_id`、`pending_id`；非当前会话的审批 fail closed | SEC-004 | 无 | 会话 ID 碰撞（极低概率） | K-004 |
| T-042 | Repudiation | 同一 request 被两个设备竞争接纳 | Critical | A-03 | 双设备竞争 | 第一个合法决定胜出；另一设备显示处理人和结果；原子解决 pending | SEC-004 | 无 | 网络分区后双端各自提交（fail closed） | K-004 |
| T-043 | Repudiation | Connector 崩溃窗口内结果不明被自动重跑 | High | A-03, A-10 | 崩溃后自动恢复 | 外部副作用成功但结果未持久化 → Turn 进入 `OutcomeUnknown`；不自动重跑 | CON-003 | 无 | 用户需要手动判断并可能重跑 | — |
| T-044 | Repudiation | Relay ACK 被误展示为 Host 接纳 | High | A-02, A-03 | 协议混淆 | Relay ACK 只表示密文被目标设备持久接收；UI 明确区分"Relay 已收到"与"Host 已接纳" | CON-003 | 无 | 用户可能忽略区别 | — |

### 5.6 跨设备与设备丢失

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-050 | Spoofing | 设备丢失后攻击者读取会话历史 | Critical | A-13, A-01 | 物理访问 | 本地加密；Secure Enclave；App 切换器隐藏；后台锁定；设备丢失后立即吊销 | MB-002/MB-013 | 无 | Secure Enclave 物理攻击（极低概率） | — |
| T-051 | Spoofing | 攻击者在设备丢失后发送恶意命令 | Critical | A-03, A-10 | 物理访问 + 解锁 | 设备丢失后立即吊销；吊销传播 P95 60 秒内；吊销后无法发送新 epoch | SEC-002 | 已吊销设备在 60 秒窗口内成功发送并接纳新命令 | 吊销延迟窗口 | K-001 |
| T-052 | Spoofing | 全部设备丢失后无法恢复 Relay 历史 | High | A-07, A-01 | 产品设计 | Validation Companion 明确不提供密钥恢复；用户理解该后果；重新配对但不能恢复历史 | SEC-002 | 无 | 用户误读恢复能力 | K-008 |
| T-053 | Spoofing | 新设备未授权被绑定到用户账户 | Critical | A-04, A-06 | 配对流程劫持 | QR + comparison code + 双端确认；QR 一次性使用、两分钟过期、单设备消费 | SEC-002 | 未经 comparison code 确认的设备成功绑定到用户账户 | 用户被社会工程诱骗扫码 | K-001 |

### 5.7 供应链与分发

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-060 | Spoofing | 被篡改的 Host Connector 安装包 | Critical | A-04, A-01 | 分发链路被劫持 | Release 产物签名；SBOM；CI 编译链可追溯 | OPS-002 | 签名验证失败的产物被成功安装并运行 | 签名密钥泄露 | — |
| T-061 | Tampering | 第三方依赖植入恶意代码 | High | A-01, A-04 | 供应链攻击 | 持续依赖扫描；许可证检查；最小依赖集 | QA-004 | 无 | 上游维护者被攻陷 | — |
| T-062 | Spoofing | Mobile App 被仿冒 | High | A-04, A-13 | App Store 分发外下载 | 仅通过 TestFlight 分发；不提供侧载链接 | MB-001 | 无 | 用户从非官方渠道获取 | — |
| T-063 | Disclosure | Build 系统泄露源代码/密钥 | High | A-01, A-04 | CI 被攻破 | 密钥注入方式；构建日志脱敏；最小权限 | OPS-002 | 无 | CI 管理员权限提升 | — |

### 5.8 网络与传输

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-070 | Disclosure | TLS 中间人攻击 | High | A-07, A-01 | 中间人 | TLS 传输加密 + 应用层 E2EE 双层防护 | SEC-003 | 无 | TLS 配置错误 | — |
| T-071 | Tampering | 企业代理/防火墙注入流量 | High | A-07, A-01 | 企业网络 | E2EE 密文对代理不透明；出站 WSS 固定目标 | SEC-003 | 无 | 企业网络阻断 WSS | — |
| T-072 | Spoofing | DNS 劫持导致连接到恶意 Relay | High | A-02 | DNS 投毒 | TLS 证书校验；证书绑定（可选） | SEC-003 | 无 | CA 被攻陷（极低概率） | — |
| T-073 | DoS | 网络降级导致会话断裂 | Medium | A-01 | 网络不稳定 | 断线恢复；有界 buffer；快照校验 | CON-004/HC-005/MB-003 | 无 | 长时间网络中断 | — |

### 5.9 元数据与隐私

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-080 | Disclosure | Relay 元数据关联用户 | Medium | A-06, A-08 | 元数据关联 | 化名化 ID；最小元数据；保留 30 天后清除 | RL-001/OPS-001/OPS-004 | 无 | 长期元数据模式 | — |
| T-081 | Disclosure | Push token 被跨服务关联 | Medium | A-08 | APNs 与 Relay 关联 | Push token 仅用于通用通知；不与用户可识别信息绑定 | MB-012/RL-007 | 无 | APNs 自身政策 | — |
| T-082 | Disclosure | 遥测数据聚合后识别用户 | Medium | A-12 | 统计分析 | 遥测字段 allowlist；保留 90 天；账户删除后 30 天清除 | RL-001/OPS-001/OPS-004 | 无 | 高级统计关联 | — |

### 5.10 产品语义边界

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-090 | Tampering | Mobile 显示的审批内容被模型文本覆盖 | High | A-02, A-03 | Prompt injection | 审批卡片只显示 Host 事实；模型说明标为"不可信说明"分区 | SEC-004 | 无 | 用户忽略分区 | — |
| T-091 | Spoofing | 同一 Session 被多个 writer 竞争写入 | Critical | A-01 | 多客户端并发 | OpenCode 为 Validation Companion 阶段唯一 Session writer；Connector 不反向写入 | HC-004/HC-010 | 检测到 Session 存在多个活跃 writer 竞争写入 | OpenCode 自身多客户端 bug | K-001 |
| T-092 | Disclosure | 手机锁屏通知显示敏感审批内容 | High | A-13 | iOS 锁屏通知 | 锁屏通知只显示通用类别；无敏感内容预览 | MB-012/RL-007 | 锁屏通知出现审批内容字段 | 用户打开锁屏预览 | K-006 |
| T-093 | Tampering | 离线审批队列中过期决定在恢复后执行 | Critical | A-03, A-10 | 过期审批被执行 | Approval/Stop 不离线排队；离线时只显示未处理但不提交 | CON-003/HC-008/MB-009/MB-011 | 过期审批（超过有效期）在恢复后被提交执行 | 用户手动恢复离线审批 | K-004 |
| T-094 | Spoofing | 已吊销设备继续读取新密文 | Critical | A-07 | 吊销未传播到 Connector | key epoch 轮换后新密文用新密钥；吊销设备无法读取新 epoch | SEC-002 | 已吊销设备成功解密新 key epoch 密文 | 吊销传播延迟 | K-001 |

### 5.11 未知/未分类

| ID | STRIDE | 威胁 | 严重度 | 资产 | 攻击向量 | 控制措施 | Owner | 停止条件 | 残余风险 | Kill Switch |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-095 | Disclosure | OpenCode Provider 请求内容被 Model Provider 泄露 | High | A-01 | Model Provider 数据政策 | 用户知晓 BYOK 不等于内容不离开本机；E2EE 不覆盖 Provider | HC-013 | 无 | 用户对边界误解 | — |
| T-096 | Spoofing | Relay 运营者拒绝为特定用户投递密文 | Medium | A-07 | 运营者主观拒绝 | 密文保留 7 天或 ACK；用户可诊断投递失败 | RL-003/RL-010 | 无 | 运营者拒绝服务风险 | — |
| T-097 | Tampering | 旧 OpenCode 版本的权限绕过 | High | A-01 | 版本未锁定 | Connector 固定 OpenCode 版本；版本不匹配时停止可写远程操作 | HC-001 | 无 | OpenCode 自身安全漏洞 | K-002 |

## 6. 风险评级与接受门槛

### 6.1 严重度标准

| 等级 | 定义 | 处理要求 |
| --- | --- | --- |
| Critical | 可能导致内容泄露、跨会话审批、密钥泄露、同一 request 重复接纳 | 发布门必须 0 个；不接受临时缓解；独立安全评审必须通过 |
| High | 需要前置条件、影响受限但违反信任模型 | Private Alpha 前 0 个；每个必须有明确控制措施与 Owner |
| Medium | 不直接违反信任模型但增加攻击面 | Private Alpha 前 0 个；必须有 Owner 和控制措施；不可延期 |
| Low | 纵深防御问题 | 有 Owner 和修复日期 |

### 6.2 控制面汇总

#### 6.2.1 Critical 威胁

| 威胁 ID | 控制措施 | Owner | 相关任务 |
| --- | --- | --- | --- |
| T-001, T-004, T-012, T-051, T-053, T-094 | 吊销传播、key epoch、设备独立密钥、配对握手 | SEC-002 | SEC-002 |
| T-003, T-010, T-011, T-040, T-041, T-042 | 签名覆盖、action hash 绑定、request_id 去重、原子竞争 | SEC-003, SEC-004, CON-003 | SEC-003, SEC-004, CON-003 |
| T-020, T-027, T-060 | E2EE 密文保护、Provider Key 隔离、产物签名 | SEC-003, HC-003, OPS-002 | SEC-003, HC-003, OPS-002 |
| T-050 | Mobile 本地加密存储、系统安全存储、后台锁定与设备吊销 | MB-002/MB-013/SEC-002 | MB-002, MB-013, SEC-002 |
| T-091 | 单 writer 约束（OpenCode 唯一 Session writer） | HC-004/HC-010 | HC-004, HC-010 |
| T-093 | 过期审批 fail closed（离线不排队） | CON-003/HC-008/MB-009/MB-011 | CON-003, HC-008, MB-009, MB-011 |

#### 6.2.2 High 威胁

| 威胁 ID | 控制措施 | Owner | 相关任务 |
| --- | --- | --- | --- |
| T-002, T-005, T-052 | key epoch 轮换、版本协商 fail closed、全部可信设备丢失后不恢复 Relay 历史 | SEC-002, SEC-003 | SEC-002, SEC-003 |
| T-013, T-023 | Mobile 加密存储、Secure Enclave、App 切换器隐藏 | MB-002/MB-003/MB-004/MB-013 | MB-002, MB-003, MB-004, MB-013 |
| T-014, T-024, T-097 | OpenCode loopback only、Connector 持久化最小化、版本锁定 | HC-003, HC-002/HC-005, HC-001 | HC-001, HC-002, HC-003, HC-005 |
| T-021, T-022, T-092 | 日志 allowlist、Push 无内容、锁屏通用通知 | RL-001/OPS-001/OPS-004, MB-012/RL-007 | RL-001, OPS-001, OPS-004, MB-012, RL-007 |
| T-030 | Relay frame 大小、每设备速率和账户容量限制 | RL-002/RL-004 | RL-002, RL-004 |
| T-031, T-034 | 重放防护（nonce+expiry+签名）、loopback 速率限制 | SEC-003, HC-003 | SEC-003, HC-003 |
| T-043, T-044 | OutcomeUnknown 语义、UI 区分 | CON-003 | CON-003 |
| T-061, T-062, T-063 | 依赖扫描、TestFlight 分发、构建安全 | QA-004, MB-001, OPS-002 | QA-004, MB-001, OPS-002 |
| T-070, T-071, T-072 | TLS+E2EE 双层、E2EE 对代理不透明、证书校验 | SEC-003 | SEC-003 |
| T-090, T-095 | 审批卡片分区展示、BYOK 用户教育 | SEC-004, HC-013 | SEC-004, HC-013 |

#### 6.2.3 Medium 威胁

| 威胁 ID | 控制措施 | Owner | 相关任务 |
| --- | --- | --- | --- |
| T-025, T-026, T-032, T-033, T-073 | 诊断包预览、App 切换器隐藏、Push 速率限制、有界 frame、断线恢复 | HC-013, MB-002/MB-013, RL-007, HC-006, CON-004/HC-005/MB-003 | HC-013, MB-002, MB-013, RL-007, HC-006, CON-004, HC-005, MB-003 |
| T-080, T-081, T-082, T-096 | 化名化 ID、Push token 最小化、遥测 allowlist、投递诊断 | RL-001/OPS-001/OPS-004, MB-012/RL-007, RL-003/RL-010 | RL-001, OPS-001, OPS-004, MB-012, RL-007, RL-003, RL-010 |

### 6.3 发布门槛（从 PRD 第 13 节映射）

- **Private Alpha 前必须为 0：** 所有 Critical/High/Medium 威胁必须有明确控制措施且通过安全回归。无 Medium 威胁延期。
- **Low 威胁：** 必须有 Owner 和修复日期。

### 6.4 BYOK 披露缺口

T-095（Model Provider 泄露）的缓解通过 HC-013 规划实施：

1. **用户首次连接时显式 BYOK 说明** — 在 HC-013 的 Connector CLI 首次连接流程中展示 Provider 数据边界与 BYOK 说明。
2. **Connector 侧 Provider 边界提示** — 在 HC-013 的 Connector CLI 与隐私安全诊断中加入 Provider 边界说明。
3. **BYOK 不等于 E2EE 的用户告知** — 通过 HC-013 规划的诊断与教育流程完成闭环。

当前状态：**已规划**。HC-013 为 T-095 的主 Owner，将在实施时完成闭环。

## 7. 残余风险汇总

以下风险在当前威胁模型下被识别但属于产品接受范围，需在用户文档中明确告知：

| ID | 描述 | 影响 | 用户知晓方式 | 后续处理 |
| --- | --- | --- | --- | --- |
| R-001 | Relay 元数据模式可能被统计关联 | 低 | 隐私政策 | 保留期结束后清除；持续监控 |
| R-002 | 设备丢失后历史密文无法恢复 | 高 | 首次配对与设置界面明确告知 | 产品 D-005 接受门槛的一部分 |
| R-003 | 吊销传播存在 60 秒延迟窗口 | 高 | 安全评审文档 | SEC-002 优化 |
| R-004 | OpenCode 自身安全漏洞超出 Nomad 信任边界 | 中 | 产品文档说明 | 固定版本 + 社区安全公告监控 |
| R-005 | Model Provider 数据政策影响用户上下文（BYOK 边界） | 高 | 首次连接时明确说明 BYOK 不等于 E2EE | 用户自主选择 Provider；HC-013 规划实施 |
| R-006 | 网络长时间中断导致移动端不可用 | 中 | UI 显示离线/Stale | 快照恢复 |
| R-007 | iOS 系统级通知预览可能泄露 | 低 | 用户需在 iOS 设置中关闭预览 | 文档指引 |
| R-008 | APNs 与 Relay 的 token 关联 | 低 | 隐私政策 | Push token 最小化使用 |

## 8. 停止条件（Security Kill Switches）

以下情况必须立即停止相关高风险能力：

| ID | 停止条件 | 停止的能力 | 触发条件 | 适用威胁 |
| --- | --- | --- | --- | --- |
| K-001 | 控制措施失败导致任何 Critical 威胁可被利用 | 所有远程可写/控制操作（reply/Stop/allow） | 安全测试发现跨会话审批、密钥泄露、重复接纳、公钥篡改、已吊销设备签发命令 | T-001, T-004, T-010, T-011, T-012, T-051, T-053, T-091, T-094 |
| K-002 | OpenCode 固定版本的权限模型无法通过原子竞争与 fail closed 验证 | 远程 allow once，降级为查看/拒绝/Stop | Fixed OpenCode Adapter 阻断验证失败 | T-014, T-097 |
| K-003 | Relay 数据库泄露暴露密文以外的内容 | 所有跨端功能 | 日志/数据库发现内容字段 | T-020, T-021 |
| K-004 | 同一 request 在自动化压力测试中被 Host 接纳两次 | 所有远程可写/控制操作（reply/Stop/allow） | `request_id` 去重逻辑失败；字段复核失败 | T-003, T-040, T-041, T-042, T-093 |
| K-005 | 密文在 7 天 retention 窗口后被解密 | 所有功能 | 密码学被破解 | T-020 |
| K-006 | Push payload 出现内容字段 | 所有远程审批/Stop | Push 审计发现内容 | T-022, T-092 |
| K-007 | 旧客户端绕过新安全检查 | 版本协商安全层 | 协议版本降级成功 | T-005 |
| K-008 | 全部设备丢失后用户预期可恢复但产品无法提供 | 账户恢复相关功能 | 用户反馈误解 | T-052 |
## 9. 复审时间表

| 里程碑 | 复审内容 | 复审人 |
| --- | --- | --- |
| SEC-002 完成 | 信任根、设备生命周期的威胁验证 | Security DRI + 独立安全评审者 |
| SEC-003 完成 | Security Envelope v0 的威胁验证 | Security DRI + 独立密码学评审者 |
| SEC-004 完成 | 远程审批的威胁验证 | Security DRI + 产品 DRI |
| Private Alpha 前 | 全部 Critical/High/Medium 威胁的控制措施验证 | Security DRI + 独立安全评审者 |
| 独立安全架构评审 | 全量威胁模型审阅 | 外部独立评审者 |
| Quarterly | 威胁模型持续更新 | Security DRI |

## 10. 已知后续任务

- SEC-002：冻结信任根与设备生命周期 ADR（依赖本文件的威胁模型）。
- SEC-003：选择成熟安全协议并冻结 Security Envelope v0（依赖本文件的控制措施清单）。
- SEC-004：定义远程审批规范化与 allowlist（依赖本文件的 T-003, T-041 分析）。
- SEC-005：发布安全测试向量与负面 corpus（覆盖本文件中 Critical/High 威胁的回归）。
- HC-013：实施 BYOK 用户教育与 Provider 边界说明（T-095 缓解）。
- ADR 需在 SEC-002 时新增：信任根与设备生命周期的 Accepted 决策。
- ADR 需在 SEC-003 时新增：Security Envelope v0 的 Accepted 决策。

## 11. 评审记录

| 日期 | 评审人 | 结论 | 备注 |
| --- | --- | --- | --- |
| 2026-08-17 | Independent Audit | Rejected | 审计发现严重度分级、Owner 映射、悬空引用、停止条件缺失等阻塞性问题 |
| 2026-08-17 | Security DRI | Draft 0.2 | 已修复全部阻塞性与高优先发现，待独立评审者签字 |
