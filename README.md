# Nomad

> 工作名。正式命名前，不对外使用该名称。

Nomad 是一个 local-first code agent。它在开发者自己的电脑上运行，通过命令行工作，并允许开发者在手机上继续查看、引导和审批同一个会话。

本仓库已完成 Stage-1 synthetic/disposable Local Validation Slice：Session
Semantics v0、Host / Relay / Mobile 参考实现和真实本地进程闭环已经通过验收。
它仍不是可发布产品；真实 OpenCode、生产安全、原生移动生命周期和外部用户价值尚未通过阶段门。

## 已确定的方向

| 事项 | 当前决定 |
| --- | --- |
| 产品切入点 | 让开发者离开电脑后，不必回到终端也能解除 Agent 阻塞 |
| 运行位置 | 默认在用户自己的电脑上，不依赖托管云开发环境 |
| 交互模型 | 同步结构化会话事件，不把 ANSI 终端直接缩小到手机上 |
| 桌面入口 | 单二进制 CLI 和 TUI |
| 移动入口 | 面向任务状态、审批、diff 和补充指令的移动客户端 |
| 核心实现 | 默认选择 Rust，但必须通过基准门槛后才能成为正式技术决策 |
| OpenCode 关系 | 以其产品行为和公开协议为参考，不做完整 fork，不承诺首版全兼容 |
| 数据原则 | 仓库原件、凭据和工具执行留在本机；发送给模型的选定上下文遵循用户所选 Provider 的数据政策；Nomad Relay 不持有会话内容密钥 |

## 产品文档

| 文档 | 内容 |
| --- | --- |
| [产品战略](docs/product/strategy.md) | 愿景、定位、目标用户、差异化和商业假设 |
| [MVP PRD](docs/product/mvp-prd.md) | 首版范围、用户流程、功能需求和验收标准 |
| [路线图](docs/product/roadmap.md) | 阶段目标、工作流、团队配置、发布门槛和风险 |
| [验证计划](docs/product/validation-plan.md) | 用户研究、原型实验、指标体系和决策规则 |
| [市场与技术调研](docs/product/research.md) | 竞品、移动连接方案、OpenCode 分析和来源 |
| [决策记录](docs/product/decision-log.md) | 已做决定、待定事项和改变决定的条件 |
| [下一迭代评估与路线图](docs/product/iteration-2-plan.md) | Stage 1 复盘、证据成熟度、阶段门、RACI 和 RAID |
| [Controlled Pilot v0.2 PRD](docs/product/iteration-2-prd.md) | 下一轮用户、范围、流程、验收和发布规则 |
| [产品需求池](docs/product/product-backlog.md) | Epic、需求 ID、RICE、依赖、DoR 和 DoD |
| [Pilot 计分卡](docs/product/pilot-scorecard.md) | Discovery、任务测试、Pilot 漏斗和 go/no-go 模板 |
| [v0.2 研究工具包](docs/product/research-kit-v0.2.md) | 招募、访谈、日记、任务测试和问题编码 |

## 产品边界

Nomad 首先解决这条完整链路：

1. 开发者在电脑上从 CLI 启动任务。
2. Agent 在本机读取代码、修改文件并运行测试。
3. 开发者离开电脑，手机仍能看到真实状态。
4. Agent 需要权限或补充信息时，手机收到通知。
5. 开发者审阅命令、diff 和风险后作出决定。
6. 任务继续运行，完成后在手机或终端查看结果。

首版不做完整移动 IDE、默认开放的远程 shell、托管云开发环境和多 Agent 团队编排。

## 当前阶段

建议下一步进入 Controlled Pilot v0.2，而不是直接进入 Internal Alpha；该建议在 M0 由产品、技术和安全 DRI 共同确认：

1. 完成 Problem Discovery 和结构化移动交互测试，先证明问题频率与用户偏好。
2. 将参考闭环替换为固定 OpenCode 版本的真实测试 Session，只使用项目提供的可丢弃仓库与临时账户。
3. 让 10 名外部候选无主持完成安装、配对，以及一次由 Host 接纳的 reply、deny 或 Stop。
4. 保持 `allow_once=false`；D-005 和 Security Envelope 未通过前不接触用户真实代码。
5. Rust Runtime 继续作为独立技术门，不能阻塞 Companion 的产品验证。

详细范围与需求见[下一迭代评估与路线图](docs/product/iteration-2-plan.md)。

### 工程实施检查点

Controlled Pilot v0.2 的内部工程纵向切片已经完成并通过多进程与浏览器验收，详见[集成报告](docs/technical/task-reports/ITER2-INTEGRATION.md)和[需求追踪矩阵](docs/technical/iteration-2-traceability.md)。

该检查点不等于外部 Pilot 已获准：官方 OpenCode `1.18.16` 的事件形态与当前兼容接口不同，真实 pending/diff 尚未验证，Pilot Security Note 尚无安全 DRI 签字，外部用户研究也尚未进行。
