# Nomad 原子任务与实施留痕约定

本目录中的任务卡用于分配给开发 agent。任务卡是实施边界，不是产品需求的替代品；发生冲突时，依次以产品决策记录、PRD、已接受 ADR 和任务卡为准。

## 状态流转

```text
Draft -> Ready -> In Progress -> In Review -> Done
                           \-> Blocked
                           \-> Cancelled
```

`Blocked` 必须写明缺少的具体输入或失败的阶段门。`Done` 必须有可复核证据。

## 分支与 PR

- 推荐分支：`feat/<task-id-lowercase>-<short-slug>`。
- 默认一个任务一个 PR；机械生成文件可随其 contract 任务提交。
- PR 标题以任务 ID 开头，例如 `CON-001 Define Session Semantics v0 schema`。
- Commit 应描述可观察的变化，不写 `misc`、`fix stuff` 或 agent 名称。

## 任务启动记录

Agent 开始任务时，在任务跟踪系统或独立任务实例中登记：

```markdown
- Task: CON-001
- Status: In Progress
- Owner: <name-or-agent-id>
- Branch/Worktree: <branch and path>
- Base commit: <sha>
- Contract/ADR versions: <versions>
- Started at: <ISO-8601>
- Assumptions: <none or explicit list>
```

不要直接修改本目录中的基线任务定义来写个人进度；完成证据使用下方模板写入任务系统、PR 描述或 `docs/technical/task-reports/<task-id>.md`。

## 最小完成留痕

```markdown
# <TASK-ID> Completion Report

- Status: Done | Blocked | Cancelled
- Owner: <name-or-agent-id>
- PR/Commit: <links-or-sha>
- Completed at: <ISO-8601>

## Outcome

一句话说明实际交付或被什么阻塞。

## Changed

- 仅列主要接口、数据或行为变化。

## Verification

- `<command>` -> PASS/FAIL，附稳定的日志、报告或测试路径。
- 手工/设备验证 -> 结果和环境。

## Decisions and deviations

- 新 ADR、与任务卡的偏差及原因；没有则写 None。

## Security and privacy

- 是否改变信任边界、可见数据、日志字段、密钥或远程操作；没有则写 None。

## Follow-ups

- 后续任务 ID；没有则写 None。
```

## 评审清单

- 任务目标可以由测试或书面 spike 证据判定。
- 没有把 Relay ACK 当成 Host accepted。
- 没有让 Connector 成为第二个 OpenCode Session writer。
- 没有在客户端私自扩展 contract。
- 内容没有进入日志、指标、Push 或诊断包。
- 高风险能力在版本、状态或上下文不确定时 fail closed。
- 数据有 owner、保留期、删除路径和迁移策略。
- 新并发状态有竞争和崩溃测试。
