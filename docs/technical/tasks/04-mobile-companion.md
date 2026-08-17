# Mobile Companion 任务

Mobile 是 Session 的客户端投影和短时决策界面，不拥有 Host 事实。Push、ephemeral delta 和本地 optimistic UI 都不能替代 durable state。

## MB-001：完成原生 iOS 与 React Native 技术 spike

- Size：M
- Depends on：CON-001、SEC-001
- 关联：PRD 待决问题
- 目标：用同一组关键场景选择 Mobile 技术栈。
- 交付：两种候选的最小原型或可复核实验；大 diff、100k timeline reducer、WSS、Push/background、Keychain/Secure Enclave、VoiceOver 和发布成本对比；ADR。
- 验收：使用相同 fixture 和设备；报告 p50/p95、内存、后台限制和维护风险；结论可被推翻的条件明确；不以团队偏好代替证据。
- 排除：完整 UI 和 Android。

## MB-002：建立 Mobile 工程骨架与安全存储

- Size：M
- Depends on：MB-001、SEC-002
- 关联：MB-07
- 目标：建立可测试的应用模块、设备身份接口和加密缓存基础。
- 交付：构建配置、模块边界、Keychain/Secure Enclave adapter、加密本地存储、环境与 feature capability。
- 验收：私钥不出安全存储；测试/生产环境隔离；退出登录/吊销/卸载可删除缓存；日志和 crash breadcrumb 无敏感内容。
- 排除：具体配对和 Session UI。

## MB-003：实现 Session reducer 与 contract conformance

- Size：M
- Depends on：CON-002、CON-004、CON-005、MB-002
- 关联：SP-01、SP-02
- 目标：从 snapshot + durable events 确定性产生 Mobile 视图模型。
- 交付：reducer、seq/gap/duplicate/version handling、snapshot verification 和 conformance runner。
- 验收：全部 golden traces 通过；重复事件无副作用；未知 gap/版本时保持 Stale；ephemeral delta 丢失后最终状态正确；100k 事件预算达标。
- 排除：网络连接和页面布局。

## MB-004：实现 Mobile sync engine

- Size：M
- Depends on：SEC-003、RL-002、RL-003、MB-003
- 关联：SP-02、PRD 7.5
- 目标：连接 Relay、解密 frame、ACK 并执行 resume/reconcile。
- 交付：WSS lifecycle、frame assembly、decrypt/verify、ACK、resume、snapshot fetch、backoff 和连接状态。
- 验收：Wi-Fi/蜂窝切换、后台 kill 和重复/乱序 frame 后收敛；校验完成前不显示 Live；吊销或未知 epoch 失败关闭；短断网恢复达到内部目标。
- 排除：Push 和命令发送。

## MB-005：实现配对与设备管理客户端

- Size：M
- Depends on：SEC-002、SEC-003、RL-005、RL-006、MB-002
- 关联：PRD 7.1、Devices 页面
- 目标：完成扫码、比较码、双端确认、设备列表和吊销。
- 交付：QR flow、expiry/replay UI、confirmation、device list/rename/revoke 和丢失设备说明。
- 验收：成功与失败状态符合安全状态机；二维码不保存长期 bearer；吊销立即清缓存并阻止命令；无密钥恢复后果清楚呈现。
- 排除：多 Host 用户体验和恢复码。

## MB-006：实现 Home 与 Host 状态页面

- Size：M
- Depends on：MB-003、MB-004
- 关联：MB-01；PRD 5.1
- 目标：优先呈现需要处理、运行中和最近活动，并准确表达 Host 在线性。
- 交付：Home/Host view models、排序/筛选、最后在线、版本、sleep/offline 提示。
- 验收：NeedsInput/NeedsPermission 优先；Offline、Stale、Completed 不互相混淆；状态不只依赖颜色；VoiceOver 和动态字体通过。
- 排除：多 Host P0 和聊天历史式无限列表。

## MB-007：实现 Session timeline 与实时增量呈现

- Size：M
- Depends on：MB-003、MB-006
- 关联：MB-02
- 目标：安全、高性能展示结构化消息、工具、测试、错误和状态。
- 交付：虚拟化 timeline、durable/ephemeral merge、bounded output、ANSI/OSC 安全处理、错误与测试卡片。
- 验收：大列表滚动无明显卡顿；未过滤控制序列不执行；ephemeral 消失后 durable 结果替换；超长工具输出有明确截断和 Host 事实。
- 排除：Raw terminal、完整 markdown 执行环境和 Session 搜索。

## MB-008：实现 reply 队列与发送状态

- Size：M
- Depends on：CON-003、MB-004、HC-007 contract
- 关联：MB-05、PRD 7.3
- 目标：提交普通文本并准确展示各层状态。
- 交付：本地草稿、request ID、send/retry、Relay received、Host accepted、applied/result 状态。
- 验收：网络重试不重复消息；Host offline/Stale 时只保留本机草稿；用户能区分 Relay 与 Host；重新启动 App 后不把草稿误作已发送。
- 排除：服务端离线命令队列和附件。

## MB-009：实现 Stop 与 interrupt-and-send 交互

- Size：M
- Depends on：MB-008、HC-008 contract
- 关联：MB-05
- 目标：提供安全 Stop 和先停止后发送的明确流程。
- 交付：Stop confirmation、Stopping UI、deferred message、失败/未知处理。
- 验收：仅 Online+Live 可提交；不做离线排队；未确认旧 turn 终态不显示新消息已应用；重复点击不会产生多次 Host 接纳。
- 排除：Terminate Host 和强杀任意进程。

## MB-010：实现 Changes 与大 diff 浏览

- Size：M
- Depends on：MB-003、HC-011 contract
- 关联：MB-04、PRD 7.4
- 目标：在手机上按摘要、文件和 chunk 审阅 workspace diff。
- 交付：统计、文件列表、unified diff、lazy chunk、binary/large/generated/rename/external-change 提示、测试摘要。
- 验收：100 文件/1 万行 fixture 中列表和首文件满足目标；超大 diff 不崩溃；基准变化显示过期；不可归因变化措辞准确；增删不只靠颜色。
- 排除：编辑、提交和 Git push。

## MB-011：实现 Approval 卡片与本地认证

- Size：M
- Depends on：MB-003、HC-009、HC-010、SEC-004；allow 路径另依赖 HC-015
- 关联：MB-03、PRD 7.2、8.2
- 目标：展示 Host 事实并提供 deny/Stop，以及在 GO 条件下的 allow once。
- 交付：工具/参数/cwd/资源/风险/expiry/action hash view；模型说明隔离；biometric gate；resolved/competing state。
- 验收：Stale/Offline/expired 无 allow；危险/未知请求不渲染 allow；Unicode/bidi 可见；竞争失败显示处理结果；HC-009 NO-GO 时仍可查看、deny/Stop，且构建能力中不存在 allow once。
- 排除：永久规则、锁屏批准和任意 shell。

## MB-012：实现 Push deep-link 与生命周期校准

- Size：M
- Depends on：RL-007、MB-004、MB-006
- 关联：MB-06
- 目标：用通用 Push 唤醒并在恢复事实后进入正确页面。
- 交付：通知类别、opaque deep-link、foreground/background handling、permission UX、late/duplicate handling。
- 验收：Push payload 无内容；点击后先恢复校验再开放操作；已解决 permission 不重新可操作；Push 关闭时状态和诊断清楚；App receipt 与 APNs accepted 分开测量。
- 排除：Push 上的快捷批准。

## MB-013：完成 Mobile 隐私保护与 App lock

- Size：M
- Depends on：MB-005..012
- 关联：PRD 10.3
- 目标：使 Mobile cache、后台预览和高风险页面受本地隐私边界保护。
- 交付：app switcher redaction、background auto-lock、解锁策略、敏感页面 blur 和本地 cache 访问控制。
- 验收：后台预览无内容；超时后必须重新认证；解锁失败不泄露 timeline/diff；退出/吊销后 cache 不可恢复；安全日志无生物特征结果细节。
- 排除：辅助功能、视觉精修和 P1 voice draft。

## MB-014：实现账户登录、退出与删除入口

- Size：M
- Depends on：MB-002、RL-009
- 关联：PRD Mobile 登录、Devices、Settings、数据删除
- 目标：建立账户会话并将账户目录权与设备内容解密权清楚分离。
- 交付：登录/刷新/退出、账户切换防护、首设备 bootstrap、删除确认与进度、认证故障诊断。
- 验收：登录成功但未配对时看不到 Session 内容；token 进入系统安全存储且不进日志；退出清理账户会话与本地内容缓存；账户切换不串数据；删除流程能追踪 Relay 删除状态。
- 排除：Provider OAuth、企业 SSO、密钥恢复和多账户并存。

## MB-015：完成 Mobile P0 可访问性

- Size：M
- Depends on：MB-006..014
- 关联：PRD 10.4
- 目标：使 Home、Session、Approval、Changes、Devices 和 Settings 满足 P0 辅助功能要求。
- 交付：dynamic type、VoiceOver labels/order/actions、reduced motion、44pt targets、非颜色状态语义和 diff 增删文本。
- 验收：系统辅助功能检查和手工设备矩阵通过；最大字体下核心操作不丢失；高风险允许与拒绝有足够距离；Live/Stale/Offline 可由屏幕阅读器区分。
- 排除：视觉品牌精修和 P1 voice draft。
