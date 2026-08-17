# Secure Relay 任务

Relay 是 opaque transport，不是 Session 状态机。任何任务都不能要求 Relay 解密、解析或索引 Session 内容。

## RL-001：冻结 Relay 模块边界与数据分类

- Size：S
- Depends on：CON-001、SEC-001
- 关联：D-005；PRD 11
- 目标：定义模块化单体、PostgreSQL schema 边界和每类数据的 owner/TTL。
- 交付：组件图；accounts/devices/pairing/mailbox/ACK/push/revocation/audit 的逻辑模型；数据分类与 deletion matrix；ADR。
- 验收：每个字段标明 Relay 可见性、日志规则和保留期；没有内容字段或内容索引；迁移与回滚 owner 明确；安全 DRI 评审。
- 排除：微服务拆分、Redis 和对象存储。

## RL-002：实现 WSS connection gateway 骨架

- Size：M
- Depends on：RL-001、SEC-003 的传输鉴权 contract
- 关联：SP-04、SP-07
- 目标：支持 Host/Mobile 出站长连接、鉴权、heartbeat、限流和能力协商。
- 交付：连接状态机、session binding、frame size/rate limit、privacy-safe metrics。
- 验收：未知 envelope/能力版本的安全操作 fail closed；恶意超限 frame 不影响其他连接；日志无 payload；重复连接和网络重置可恢复。
- 排除：Session reducer 和消息解密。

## RL-003：实现 opaque mailbox 与 per-device ACK

- Size：M
- Depends on：RL-001、RL-002
- 关联：SP-02、PRD Relay 范围
- 目标：为离线目标提供短期密文补发。
- 交付：mailbox frame、chunk metadata、per-device delivery/ACK、TTL、幂等写和读取游标。
- 验收：至少一次投递下重复安全；ACK 只删除对应设备的密文资格；七天或所有目标 ACK 的较早条件可表达；数据库泄露样本仅含密文和声明元数据。
- 排除：Host command 接纳和明文搜索。

## RL-004：实现 retention、容量和 backpressure worker

- Size：M
- Depends on：RL-003
- 关联：PRD 11.4、HC-07
- 目标：限制 Relay 数据增长并使超限行为可诊断。
- 交付：TTL 清理、ACK 清理、账户/设备容量、超限错误、指标和恢复 runbook。
- 验收：删除幂等；缓存和备份生命周期有验证；大消息/恶意设备不能无限占用；容量错误不伪装成消息已送达；不通过内容类型判断优先级。
- 排除：付费配额和跨区域复制。

## RL-005：实现短期配对协调服务

- Size：M
- Depends on：SEC-002、RL-001
- 关联：PRD 7.1
- 目标：协调二维码配对而不持有长期 bearer secret 或内容密钥。
- 交付：pairing session、两分钟 TTL、单次消费、双端确认状态、比较码输入材料和重放审计。
- 验收：任一端未确认不能完成；过期/消费/重放失败；并发消费只有一个成功；日志不含配对秘密；失败有稳定错误码。
- 排除：替设备生成私钥和密钥恢复。

## RL-006：实现 device directory 与吊销传播

- Size：M
- Depends on：SEC-002、RL-001、RL-002、RL-009
- 关联：SP-05
- 目标：维护设备公钥、key epoch、状态和吊销版本。
- 交付：device registration、list、rename、revoke、revocation version/notification 和 stale-device rejection。
- 验收：吊销后 P95 60 秒内新连接/命令失效；旧 epoch 不可用于新消息；并发吊销幂等；目录不存内容密钥。
- 排除：团队设备策略和 SSO。

## RL-007：实现 transactional Push outbox

- Size：M
- Depends on：RL-003、RL-006
- 关联：MB-06；PRD Push 目标
- 目标：可靠触发无内容的 APNs 通知，并与 mailbox 写入保持一致。
- 交付：push outbox、类别映射、opaque deep-link、重试、token invalidation 和分段指标。
- 验收：payload 自动扫描不含 Prompt/路径/命令/diff；mailbox 未持久化时不发送成功 Push；重复/晚到 Push 不改变事实；Provider accepted 与 App receipt 分开报告。
- 排除：锁屏批准和在 Push 中携带状态正文。

## RL-008：实现 Relay 账户删除与数据生命周期验证

- Size：M
- Depends on：RL-004、RL-006、RL-009
- 关联：PRD 11.4、13
- 目标：使账户、设备、密文、路由元数据和 Push token 按声明生命周期删除。
- 交付：账户删除 workflow、级联/异步删除状态、备份清理标记、删除审计和自动验证。
- 验收：主库、在线缓存、Push、分析和备份生命周期均有 deletion test；恢复不重新激活已过删除期限的数据；重复删除幂等；用户可查询删除进度。
- 排除：公开 SLA、区域故障演练和计费。

## RL-009：实现账户认证与设备 bootstrap

- Size：M
- Depends on：SEC-002、RL-001、RL-002
- 关联：PRD Mobile 登录、Provider 与平台数据边界
- 目标：在不把账户登录等同于内容解密权的前提下，为 Private Alpha 建立账户会话和首设备 bootstrap。
- 交付：认证 provider/流程 ADR、account session、token rotation/revocation、首设备注册证明、账户与设备的稳定 opaque ID、登录诊断。
- 验收：Relay 账户会话不能单独解密 Session；认证重放、过期 token、账户切换和被吊销设备均失败；日志不含完整 token；账户删除能枚举其设备和 Relay 数据；恢复边界符合 SEC-002。
- 排除：企业 SSO、组织、多因素恢复和 Provider API Key。

## RL-010：建立 Relay 部署、迁移、回滚与故障基线

- Size：M
- Depends on：RL-002..004、RL-007、OPS-001、OPS-002
- 关联：路线图 11-13；PRD 13
- 目标：让单区域 Alpha Relay 可重复部署、迁移、回滚和恢复。
- 交付：部署 manifest、数据库 migration、rollback/runbook、容量和 SLO dashboard、告警、备份恢复与区域/数据库故障演练。
- 验收：migration 前进/回退可演练；恢复保持 mailbox/ACK/outbox 不变量；dashboard 无内容或高基数敏感标签；至少完成一次数据库和连接 gateway 故障演练。
- 排除：多区域 active-active、公开 SLA 和自动跨区故障转移。
