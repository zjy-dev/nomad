# Nomad 技术设计索引

本目录把 `docs/product/` 中的产品愿景、PRD、阶段门和决策转换为技术边界与可分配任务。本轮只有设计文档，不包含产品代码实现。

## 阅读顺序

1. [产品技术架构](architecture.md)：系统边界、组件、协议分层、数据流、一致性、安全和演进策略。
2. [技术实施计划](implementation-plan.md)：阶段门、并行波次、所有权和合流规则。
3. [原子任务目录](tasks/README.md)：任务状态、分支/PR 和完成留痕约定。
4. [架构决策约定](adr/README.md)：何时必须新增 ADR 以及最小模板。

## 原子任务组

- [基础协议与安全](tasks/01-contract-security.md)
- [Host Connector](tasks/02-host-connector.md)
- [Secure Relay](tasks/03-secure-relay.md)
- [Mobile Companion](tasks/04-mobile-companion.md)
- [质量、发布与运维](tasks/05-quality-operations.md)
- [Native Runtime Spike](tasks/06-runtime-spike.md)

新增任务使用[任务模板](task-template.md)，完成后按原子任务目录中的 Completion Report 模板留痕。
