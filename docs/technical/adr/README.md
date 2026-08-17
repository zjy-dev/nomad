# Nomad 架构决策记录约定

架构决策使用轻量 ADR 留痕。产品方向仍以 `docs/product/decision-log.md` 为准；ADR 只记录实现层面的选择，不得悄悄改变产品范围或阶段门。

## 状态

- `Proposed`：正在评审或等待 spike 证据。
- `Accepted`：当前实现必须遵守。
- `Superseded`：被新 ADR 替代，旧文件保留并链接替代项。
- `Rejected`：已评估但不采用。

## 文件命名

```text
ADR-0001-short-title.md
```

编号只递增，不复用。

## 最小模板

```markdown
# ADR-NNNN：标题

- 状态：Proposed | Accepted | Superseded | Rejected
- 日期：YYYY-MM-DD
- 决策者：角色或姓名
- 关联：产品决策、需求 ID、任务 ID、PR

## 背景

要解决的问题、约束和已有证据。

## 决策

可以被实现和测试的一句话决定。

## 备选方案

列出真正评估过的方案和不采用原因。

## 影响

正面、代价、迁移和运维影响。

## 验证与复审

验证方式、停止条件和复审时间。
```

## 必须新增 ADR 的变化

- 改变 Session owner、单 writer 或数据权威归属。
- 改变协议兼容、持久事件、命令幂等或 `OutcomeUnknown` 语义。
- 选择或替换安全协议、信任根、密钥轮换和恢复模型。
- 选择 Mobile、Connector、Relay 或 Runtime 的长期技术栈。
- 引入新的持久存储、消息系统、缓存或跨服务事务。
- 改变 Relay 可见数据、retention 或遥测边界。
- 改变远程 allowlist 或 Host 最终裁决规则。
