# ADR-0001：Host Connector 技术栈选择——Rust vs Go

- 状态：Proposed
- 日期：2026-08-17
- 决策者：待指定（Technical DRI 任命后由其确认接受）
- 关联：HC-002、PRD SP-01（Connector 性能指标）、PRD 第 3.1 节（Connector 范围）

## 背景

Nomad Validation Companion 的 Host Connector 是一个长期运行的本地进程，负责：

1. 连接固定版本的 OpenCode loopback Server，读取 Session / Message / Tool / Permission / Diff 语义。
2. 管理设备配对、密文传输游标、恢复快照。
3. 通过 SSE 将事件推送到 Secure Relay，接收来自 Mobile 的命令。
4. 不写入 OpenCode Session 数据，不暴露公网端口。

PRD 对 Connector 提出了硬性能约束：

| 指标 | 目标 |
|------|------|
| Connector 冷启动至 Ready P95 | < 1 s（不含 OpenCode 启动） |
| Connector 空闲 RSS P95 | < 75 MB |
| 十万持久事件恢复 P95 | < 2 s，峰值 RSS < 200 MB |
| Host 到 Mobile 事件延迟 P50 / P95 | < 250 ms / < 800 ms |

两个候选语言是 Rust 和 Go。两者都能提供静态编译、单二进制分发、跨平台（macOS/iOS）支持，但在内存占用、冷启动、运行时和团队维护风险上存在差异。本 ADR 依据 HC-002 双栈 spike 产出的实测数据，作出实现层面的选择。

## 决策

Host Connector 拟采用 **Rust** 实现，使用 `tokio` 异步运行时、`axum` HTTP/SSE 栈、`rusqlite` 作为嵌入式持久存储。

本决策状态为 Proposed，待 Technical DRI 确认接受后转为 Accepted。Go 作为备选保留：若后续 iOS 端或 CI 环境证明 Rust 版本在关键路径上出现不可接受的维护阻塞，可通过 ADR-0002 重新评估。

## 备选方案

### 方案 A：Go（被拒绝）

| 维度 | 评估 |
|------|------|
| 冷启动 P95 | 5.99 ms（Run 3，三次均值区间 6–8 ms）— 满足 < 1 s 目标 |
| 空闲 RSS P95 | 11.4 MB — 满足 < 75 MB 目标（但 Rust 是 1.78 MB，为其 6.4 倍） |
| 十万事件恢复 | 未在 spike 中直接测量，不可从 5000 事务基准线性外推；需 HC-005 验证 |
| 二进制大小 | 13.0 MB — Rust 的 6.3 倍 |
| 动态库依赖 | 5 个（libresolv、CoreFoundation、Security、libSystem、dylib loader） |
| 团队上手 | Go 通常快于 Rust；本团队已有 Go 开发经验 |
| 内存安全 | Go GC 确定性强，但不可控于 RSS 抖动和 GC 暂停 |
| 依赖审计面 | Go runtime 依赖 5 个动态库，闭源第三方依赖需逐个审计 |

拒绝原因：空闲 RSS 虽然绝对值达标，但运行时本身占用的常驻内存是 Rust 的 6.4 倍，在长期待机场景下会持续消耗更高的物理内存。Binary 大小 13 MB 对移动推送负载和分发也有不必要的体积成本。Go GC 暂停在高负载下虽不致命，但在 Connector 需要实时响应 Mobile 命令的场景中增加了延迟上界的不确定性。团队短期上手优势存在，但长期维护的内存安全、可控资源消耗和依赖审计面窄三个维度不占优。

### 方案 B：Rust（Proposed）

| 维度 | 评估 |
|------|------|
| 冷启动 P95 | 4.09 ms（Run 3，三次均值区间 4–5 ms）— 远超 < 1 s 目标 |
| 空闲 RSS P95 | 1.78 MB — 仅为 PRD 上限的 2.3% |
| 十万事件恢复 | 未在 spike 中直接测量；需 HC-005 验证 |
| SSE 端到端延迟 | P50 0.192 ms，与 Go 基本持平 |
| SQLite WAL 5000 事务 | 总耗时 3.50 ms（prepare-once-then-reuse），略快于 Go 的 4.39 ms |
| 二进制大小 | 2.06 MB — 单文件分发，codesign 通过 |
| 动态库依赖 | 3 个（libiconv、libSystem、dylib loader） |
| 内存安全 | 编译期保证；无 GC 暂停；RSS 完全可控 |
| 依赖审计面 | 3 个动态库；无闭源第三方 runtime |

## 影响

### 正面

1. **内存预算宽松。** 空闲 RSS 1.78 MB 意味着即使后续增加 Relay 客户端、设备管理器、遥测管道等组件，整体 RSS 仍可大幅低于 75 MB 上限，为功能扩展预留空间。
2. **冷启动安全边际充足。** 4.09 ms 比目标低两个数量级，即使加上 OpenCode 子进程启动和版本校验，仍可保证 P95 < 1 s。
3. **单一分发单元。** 2.06 MB 带 codesign，无外部运行时依赖，简化 `nomad pair` 和 `nomad doctor` 的安装检查。
4. **长期维护安全。** 编译期内存安全消除了 Connector 作为本地守护进程的 use-after-free、数据竞争和缓冲区溢出风险；依赖树更浅，供应链审计成本更低。

### 代价

1. **团队学习曲线。** 若当前团队 Rust 经验不足，前 2–3 个迭代的开发速度会低于 Go。需要在 HC-004 之前安排最小的 Rust 加速（所有权、生命周期、`async/await`、`tokio::spawn` 基础）。
2. **编译时间。** 首次构建（`cargo build --release`）比 Go 慢；但 Nomad CI 可缓存 target 目录，增量构建影响可控。
3. **十万事件恢复性能未验证。** 本 spike 仅完成 5000 事务级别的 SQLite WAL 基准，实际恢复管线的 P95 和峰值 RSS 需在 HC-005 中验证。若验证结果跌破 PRD 上限，需重新评估。

### 迁移和运维

- Rust 和 Go spike 均已完成，无生产代码在本决策中丢失。
- 未来若切换回 Go，需重写 `connector/` 下全部代码并重新验证 PRD 性能指标。此成本通过 ADR 编号留痕，明确拒绝。

## 验证与复审

本决策的验证条件：

1. HC-002 spike 数据已归档于 `spikes/connector-stack/data/results.json`。
2. HC-004（Connector 适配器实现）必须以 Rust 代码提交并通过 PRD SP-01 中列出的冷启动、RSS、恢复指标的 smoke test。
3. HC-005（恢复管线）必须验证十万事件恢复 P95 < 2 s、峰值 RSS < 200 MB。若任一指标跌破 PRD 上限，技术负责人需在 48 小时内评估是否触发 ADR-0002（重新评估 Go）。

复审时间：在 HC-005（恢复管线）完成后进行一次复审，确认十万事件恢复场景下的实际表现。若 Rust 方案无法在十万事件场景下稳定保持 P95 < 2 s，需重新评估。
