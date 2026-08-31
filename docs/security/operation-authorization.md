# SVLT 操作授权模型

SVLT 不再把 `locked` 当作 Agent 的全局工作流门禁。`locked` 只保留在兼容状态中；Agent 应读取 `available`、`ready` 和 `approvalPending`，然后直接提交具体的受保护操作。

## 决策流程

每个使用 SVLT-managed Secret 的请求都经过同一条本地路径。用户明确选择其他 provider 或当前明文的操作不由 SVLT 强制接管，也不应被已有 Catalog 记录抢占：

```text
opaque descriptor
  -> normalize destination / command / path
  -> SecretOperationPolicyEngine
  -> local requirement: none | reusableApproval | freshApprovalRequired
  -> AgentRiskAssessment shown as display/audit metadata only
  -> technical failure or owner approval / scoped lease
  -> capability preflight
  -> exact device-owner approval or scoped execution lease
  -> latest policy check
  -> resolve and execute
```

`AgentRiskAssessment` 只有显示和审计作用，不能升级、降级或拒绝本地策略已经计算出的授权结果。技术性错误（格式、引用集合、目标字段或身份不可验证）会在认证前失败；其他技术上可执行的请求由设备所有者通过 Touch ID/密码决定。

## 风险规则

| 操作 | 默认状态 | 关键条件 |
| --- | --- | --- |
| 状态、使用策略、引用元数据 | `silent` | 不解密、不返回 Secret |
| 已绑定或未绑定目标的 Secret-bearing SSH/HTTP/API/数据库/SFTP 操作 | `reusableApproval` | 首次认证打开当前 scope 的固定 300 秒窗口；目标/协议提示不额外升级 |
| SSH 电源控制、文件删除、块设备/文件系统破坏、存储/RAID 破坏、容器破坏 | `freshApprovalRequired` | 只匹配固定五类；raw shell、多行、wrapper 和未知命令本身不构成额外类别 |
| HTTP `DELETE`、明文 `http://` 携 Secret、凭据 query 参数 | `freshApprovalRequired` | 固定 HTTP fresh registry；跨 origin redirect 只是 transport stop |
| 数据库 DROP/TRUNCATE/DELETE/破坏性 ALTER/权限账户管理 | `freshApprovalRequired` | 固定数据库 fresh registry |
| SFTP 删除、覆盖、替换目标 | `freshApprovalRequired` | 固定 SFTP fresh registry |
| 明文显示、复制、删除或安全设置变更 | `freshApprovalRequired` | 使用 `deviceOwnerAuthentication` |
| `localExecution`（交给任意本地进程） | `freshApprovalRequired` | 明确标记 `userApprovedSecretRelease`，由设备所有者决定 |

Secret metadata 支持 `allowedDestinations` 和 `allowedProtocols`。目的地使用规范化后的主机和端口做精确匹配；不匹配是提示并进入新的普通 scope，元数据缺失或引用集合无法验证才是技术性失败。HTTP 禁止自动跟随跨 origin 重定向，发现新主机时必须重新提交一个独立操作。

## ApprovalTicket

审批票据是一次性、默认 90 秒有效的本地 actor 状态。票据绑定：

- operation hash、action、Secret reference IDs
- 规范化目的地、端口、协议
- command hash、HTTP method/path、数据库首操作、file target
- issued/expiry 时间和 nonce

批准完成后，服务只消费与原描述符完全匹配的票据。修改 Secret、目标、命令、URL、HTTP method 或文件目标都会使旧票据失效；消费后不能 replay。

对可执行的 `approvalRequired` 操作，设备认证完成后最多建立一个固定 300 秒的
内存 lease。Lease 绑定调用主体、完整的 `secret://` 引用集合、规范化目标和端口、
协议、执行动作类型以及 security generation；它不是全局授权。每个后续请求仍会
先做 executor capability preflight，再重新读取 metadata 和执行策略；执行器失败或
transport/session 失败只报告该次执行失败，不清除已经建立的 owner lease，直到其
固定期限到达。Lease 有效期使用 monotonic clock，墙上时间只用于审计展示。

本地明文导出使用独立但同样固定 300 秒的 scope：调用主体、完整引用集合、
`exportPlaintext` 动作、经验证的 export root 和 security generation。叶文件名不属于
scope，因此同一导出目录中的不同新文件可以复用；不同引用、调用主体、根目录或安全
代际不能复用。活跃 lease 只保留该 scope 专用的内存解密 capability，不能借用更宽的
credential key cache 延长 Agent 侧 user-presence 授权。明文显示和复制仍保持 exact、
one-shot 认证。

## 明文边界

低风险解密发生在 `SVLTAgent` 的进程内。MCP 只发送 `SecretOperationDescriptor`，其中包含不透明 `secret://` 引用和非敏感参数；普通 Agent IPC 的类型和响应中不存在 `restoreReferences`、`RestoredParagraph` 或其他明文返回形状。需要本地 UI 明文的 session reveal、Catalog 字段 reveal 和 restore 只通过额外的、经过代码签名身份校验的 App-control socket 传输。专用 executor 只返回脱敏结果，并拒绝把 SVLT 派生 Secret 传入通用 shell、CLI 参数、环境变量、URL query 和日志。用户独立提供的明文不由 SVLT 与 `secret://` 做值比较，但仍受选定工具、仓库和工作区安全规则约束。

危险操作的认证使用 macOS `deviceOwnerAuthentication`，由系统选择 Touch ID 或登录密码 fallback。审批提示只显示动作、目标、Secret label 和风险原因，不显示 Secret 内容。

## 当前边界

SSH、HTTP/API 的 purpose-built executor 已接入 Agent。数据库、SFTP、浏览器和本地 App 的策略与不透明 IPC 描述符已接入，但当前 release 对应 executor 仍返回 `ACTION_EXECUTOR_UNAVAILABLE`，不会降级到明文或通用命令。QNAP 的真实 SSH/API 验收需要在有明确绑定的测试 Secret 和设备可达时执行；自动化测试覆盖 QNAP 目标形态与风险决策，不伪造真实设备成功结果。
