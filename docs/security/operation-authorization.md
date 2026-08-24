# SVLT 操作授权模型

SVLT 不再把 `locked` 当作 Agent 的全局工作流门禁。`locked` 只保留在兼容状态中；Agent 应读取 `available`、`ready` 和 `approvalPending`，然后直接提交具体的受保护操作。

## 决策流程

每个使用 SVLT-managed Secret 的请求都经过同一条本地路径。用户明确选择其他 provider 或当前明文的操作不由 SVLT 强制接管，也不应被已有 Catalog 记录抢占：

```text
opaque descriptor
  -> normalize destination / command / path
  -> SecretOperationPolicyEngine
  -> max(agentRisk, localRisk)
  -> silent | approvalRequired | denied
  -> only then resolve and execute
```

`AgentRiskAssessment` 只有审计和辅助作用。它可以把风险提高，不能把本地判断出的审批或拒绝降级。

## 风险规则

| 操作 | 默认状态 | 关键条件 |
| --- | --- | --- |
| 状态、使用策略、引用元数据 | `silent` | 不解密、不返回 Secret |
| 已绑定目标的 SSH 只读命令 | `silent` | 命令无 shell 运算符、通配符或重定向 |
| 已绑定目标的 HTTP `GET` / `HEAD` | `silent` | URL 无凭据，query 不含凭据字段 |
| 单条 `SELECT` / `EXPLAIN` / `SHOW` / `DESCRIBE` | `silent` | 无多语句、注释或写操作 |
| SFTP `list` | `silent` | 目的地和协议通过绑定检查 |
| 未绑定私有目标 | `approvalRequired` | 显示目标和 Secret label，不显示秘密 |
| HTTP `POST` / `PUT` / `PATCH` / `DELETE` | `approvalRequired` | 每个请求单独判断 |
| SSH 写入、删除、服务管理、重启等 | `approvalRequired` | 实际命令重新解析 |
| SFTP 上传、覆盖、删除 | `approvalRequired` | 不得由 Agent 风险提示降级 |
| 明文显示、复制、导出或写回 | `approvalRequired` | 使用 `deviceOwnerAuthentication` |
| 公网未绑定外发、通用 shell、无法复核的请求 | `denied` | 不自动执行 |

Secret metadata 支持 `allowedDestinations` 和 `allowedProtocols`。目的地使用规范化后的主机和端口做精确匹配；未绑定公网目标拒绝，未绑定私有目标审批。HTTP 禁止自动跟随重定向，发现新主机时必须重新提交操作。

## ApprovalTicket

审批票据是一次性、默认 90 秒有效的本地 actor 状态。票据绑定：

- operation hash、action、Secret reference IDs
- 规范化目的地、端口、协议
- command hash、HTTP method/path、数据库首操作、file target
- issued/expiry 时间和 nonce

批准完成后，服务只消费与原描述符完全匹配的票据。修改 Secret、目标、命令、URL、HTTP method 或文件目标都会使旧票据失效；消费后不能 replay。

## 明文边界

低风险解密发生在 `SVLTAgent` 的进程内。MCP 只发送 `SecretOperationDescriptor`，其中包含不透明 `secret://` 引用和非敏感参数；MCP 不使用 `restoreReferences` 获取明文。专用 executor 只返回脱敏结果，并拒绝把 SVLT 派生 Secret 传入通用 shell、CLI 参数、环境变量、URL query 和日志。用户独立提供的明文不由 SVLT 与 `secret://` 做值比较，但仍受选定工具、仓库和工作区安全规则约束。

危险操作的认证使用 macOS `deviceOwnerAuthentication`，由系统选择 Touch ID 或登录密码 fallback。审批提示只显示动作、目标、Secret label 和风险原因，不显示 Secret 内容。

## 当前边界

SSH、HTTP/API 的 purpose-built executor 已接入 Agent。数据库、SFTP、浏览器和本地 App 的策略与不透明 IPC 描述符已接入，但当前 release 对应 executor 仍返回 `ACTION_EXECUTOR_UNAVAILABLE`，不会降级到明文或通用命令。QNAP 的真实 SSH/API 验收需要在有明确绑定的测试 Secret 和设备可达时执行；自动化测试覆盖 QNAP 目标形态与风险决策，不伪造真实设备成功结果。
