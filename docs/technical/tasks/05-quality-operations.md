# 质量、发布与运维任务

质量任务产出阶段门证据，但无权单独宣布产品、安全或 Runtime 阶段通过。测试报告必须保留环境、版本、fixture、原始成功/失败次数和可复现命令。

## QA-001：建立跨实现 contract conformance runner

- Size：M
- Depends on：CON-001；随 CON-002..005 增量扩展
- 关联：路线图 4.0、4.2
- 目标：让 Host、Mobile、Relay envelope 和 Runtime 使用同一测试向量。
- 交付：manifest 驱动的 runner；schema、golden trace、snapshot 和负面向量接口；CI 报告。
- 验收：每个实现可独立运行；失败展示最小语义 diff；runner 不绑定单一语言生成类型；contract version 与实现能力写入报告。
- 排除：产品 E2E 和性能基准。

## QA-002：建立 fake OpenCode 与 record/replay harness

- Size：M
- Depends on：HC-001、CON-005
- 关联：HC-02、Adapter 阻断验证
- 目标：在不调用真实 Provider 的情况下稳定验证 adapter 和竞争场景。
- 交付：HTTP/SSE fake、snapshot mutation、pending permission、desktop/mobile race、disconnect 和 crash script。
- 验收：可重放固定版本全部核心 fixture；可以注入重复、乱序、断流、上游重启和 pending 变化；测试结果确定且不依赖公网。
- 排除：伪造上游已经具备的能力来使 spike 通过。

## QA-003：建立网络与进程故障注入平台

- Size：M
- Depends on：RL-002、RL-003、HC-006、MB-004
- 关联：Validation 6.1-6.2
- 目标：可重复注入网络、生命周期和存储故障，并核对最终不变量。
- 交付：10% loss、500ms RTT、reorder/duplicate、Wi-Fi/5G 等效切换、Relay reset、Connector kill、OpenCode restart、disk full 场景；结果收集器。
- 验收：每次机会有唯一 trace 和独立分母；自动判断 gap、snapshot、duplicate acceptance 和 `OutcomeUnknown`；失败保留最小复现；不混合真实恢复样本。
- 排除：以小样本宣称 99.5% 和人工修改报告。

## QA-004：建立安全回归与隐私扫描流水线

- Size：M
- Depends on：SEC-005、HC-006、RL-007、MB-012
- 关联：PRD 10.3、13
- 目标：持续检测重放、错误绑定和内容进入非内容通道。
- 交付：安全 corpus runner；日志/metrics/trace/Push/diagnostic fixture scanner；Secret scanning；dependency/license/SBOM checks。
- 验收：安全向量任一误接受即阻断；故意植入的 Prompt/路径/命令/diff 被扫描发现；Push 使用字段 allowlist；扫描规则有误报处置和 owner。
- 排除：以自动扫描替代独立安全评审。

## QA-005：实现 disposable-repo 端到端 P0 测试

- Size：M
- Depends on：HC-013、RL-007、MB-014、MB-015、QA-002、QA-003
- 关联：PRD 7、13
- 目标：用固定 OpenCode release 和可丢弃仓库验证用户闭环。
- 交付：安装/配对、查看、reply、deny、Stop、条件式 allow、diff、Push、恢复、吊销和删除的自动/半自动场景。
- 验收：每个 PRD P0 流程有稳定 case ID；NO-GO permission 配置下测试期望正确降级；报告记录 macOS/iOS/OpenCode/协议版本；失败可从 privacy-safe trace 定位。
- 排除：真实用户留存和真实仓库安全门。

## QA-006：执行 Private Alpha 发布门验证

- Size：M
- Depends on：QA-003、QA-004、QA-005、OPS-001、OPS-002 和全部 P0 修复任务
- 关联：PRD 13
- 目标：逐项生成可审计的发布证据包，供产品、技术和安全 DRI 决策。
- 交付：600 次预登记自动恢复原始结果；20 次八小时恢复；审批重放/竞争/mutation/expiry；强杀与重启；Push 扫描；缺陷清单；签字 checklist。
- 验收：原始结果和失败复盘可追溯；不同分母不混合；所有已知 P0、Security Critical/High/Medium 状态符合 PRD；结论明确为 GO/NO-GO/降级 GO。
- 排除：替 DRI 接受风险或用平均值掩盖失败。

## OPS-001：建立 privacy-safe 可观测性与事件响应

- Size：M
- Depends on：RL-001、CON-003、SEC-001
- 关联：PRD 11、路线图 12
- 目标：在不采集内容的情况下定位连接、恢复、Push 和命令链路故障。
- 交付：错误码、trace correlation、metrics、dashboard、alert、security/reliability incident runbook 和访问控制。
- 验收：能区分 Relay received/Host accepted/final result；能分段测 Push；标签无内容和高基数原始值；样例事故从告警到定位可演练；安全事件有停止扩量流程。
- 排除：Session 正文采样和生产内容回放。

## OPS-002：建立版本、制品、迁移与回滚流水线

- Size：M
- Depends on：CON-005、HC-002、MB-001、RL-001
- 关联：路线图质量条款、PRD 13
- 目标：对 Connector、Relay、Mobile、contracts 和固定 OpenCode 版本形成可追溯发布。
- 交付：版本矩阵、signed artifacts、SBOM、migration check、上一稳定版本回滚和 release manifest。
- 验收：不兼容版本能只读或 fail closed；数据库 migration 有前滚/回滚演练；制品来源可验证；release manifest 包含 contract/envelope/OpenCode 精确版本；上一版本恢复路径可用。
- 排除：公开商店发布和 v1 SLA。

## OPS-003：建立多 lane 仓库骨架与基础 CI

- Size：M
- Depends on：HC-002、MB-001、RL-001、QA-001
- 关联：技术架构 14；实施计划 3、8
- 目标：由单一 merge owner 创建支持 Contract、Host、Relay、Mobile、Quality 和 Runtime Spike 并行开发的仓库边界。
- 交付：目录骨架、CODEOWNERS/等价所有权、按路径触发的 build/lint/test、共享工具版本、锁文件策略、开发环境说明和 secret-safe CI。
- 验收：每个 lane 可独立执行最小验证；contract/migration/根锁文件有唯一合流 owner；CI 不输出 Secret；无关 lane 变更不触发全部昂贵任务；本地命令与 CI 一致。
- 排除：创建尚未决策的产品实现、统一所有语言的内部框架和在根目录共享业务类型。

## OPS-004：定义并实现 privacy-safe 产品分析

- Size：M
- Depends on：CON-003、SEC-001、RL-009、OPS-001
- 关联：PRD 11.2-11.5；Validation 7-8
- 目标：支持安装、配对、跨端激活和留存决策，同时不采集 Session 内容。
- 交付：事件字典、稳定化名 ID、consent 状态、漏斗计算、90 天 retention、删除接口和数据质量检查。
- 验收：事件只含 allowlist 字段；拒绝遥测的用户不进入量化 cohort；远程推进严格要求 Host accepted + durable progress + terminal state；Stop/deny 单列止损；账户删除清理可关联记录；小样本报告绝对人数。
- 排除：Prompt/代码/路径/命令/参数、录屏、用 approval 数量作为成功指标。
