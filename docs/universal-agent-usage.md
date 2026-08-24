# SVLT 通用 Agent 使用文档

本文面向 Codex、Claude、Hermes 以及其他支持 MCP 的本地或桌面 Agent。SVLT 是 opt-in：目标是让 Agent 在用户选择 SVLT 管理的秘密时使用 `secret://...` 密文引用，而不是接触这些秘密的明文；SVLT 不接管所有可用凭据。

## 1. Agent 必须理解的边界

SVLT 管理路径的正确使用方式是：

1. SVLT 管理的聊天、笔记、任务描述里只保留 `secret://...`。
2. Agent 不主动索要明文；如果用户亲自提供明文并明确要求本次使用，必须尊重这一选择，不得强制导入 SVLT。
3. Agent 不把解密后的密码、token、Authorization header、cookie、session key、填充后的敏感字段返回聊天。
4. 用户明确选择 SVLT 时，Agent 调用 SVLT MCP 工具；用户明确选择其他 provider 或当前明文时，调用用户选定的工具。
5. 明文只短暂存在于本机 macOS App、MCP server 内部或专用本地 runner 中。

Agent 不应该把 `secret://...` 当成可读信息。它只是一个不透明引用。SVLT 不比较用户独立提供的明文与引用背后的值。

来源优先级（每个 operation 独立计算）：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 没有指定时才自动发现。上一轮的 provider 选择不是永久状态；仅仅出现 password、token、API key 等词不会自动激活 SVLT。

## 2. 普通用户本机安装

普通用户不需要 Xcode，也不需要打开项目源码。

安装方式：

1. 解压 `SVLT-release.zip`。
2. 双击里面的 `install.command`。如果 macOS 拦截，右键点它再选“打开”。终端用户可以运行 `install.sh`。
3. 安装脚本会打开 SVLT。
4. 安装脚本会生成 MCP 配置文件。

安装后的固定位置：

- App：`/Applications/SVLT.app` 或 `~/Applications/SVLT.app`
- MCP server：`~/Library/Application Support/AgentSecretVault/MCP`
- MCP 配置：`~/Library/Application Support/AgentSecretVault/svlt.mcp.json`

普通用户只需要安装 Node.js 24 或更新版本，用来运行 MCP server。不需要安装 Xcode。

## 3. 通用 MCP 配置

安装完成后，打开这个文件：

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

它的内容类似：

```json
{
  "mcpServers": {
    "svlt": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
```

如果客户端是表单配置：

- Name：`svlt`
- Command：`/bin/zsh`
- Args 第一项：`-lc`
- Args 第二项：`exec node "$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js"`
- Transport：`stdio`

配置完成后重启或刷新 Agent 客户端。

## 4. Codex 安装方式

### 4.1 安装 Codex skill

如果用户拿到的是 release 包，不需要这一步；直接把第 3 节 MCP 配置粘贴到 Codex 即可。

如果用户是从源码仓库安装 Codex skill：

```bash
./scripts/install-codex-skill.sh
```

然后重启 Codex 或刷新 skills。

### 4.2 使用项目内 Codex plugin

项目内插件目录：

```text
plugins/svlt
```

插件包含：

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `skills/svlt/SKILL.md`
- `hooks/validate_secret_output.js`

如果 Codex 支持从本地目录加载插件，选择上述目录。加载后，Codex 应能看到：

- MCP server：`svlt`
- Skill：`svlt`
- Hook：`validate-secret-output`

## 5. Claude / Hermes / 其他 Agent 安装方式

Claude、Hermes 或其他客户端通常没有 Codex skill 格式。做法是：

1. 安装 MCP server，使用第 3 节的 MCP 配置。
2. 把第 6 节的“敏感信息使用策略”加入该客户端的系统提示、项目规则、profile instruction 或 workspace instruction。
3. 重启客户端。
4. 让 Agent 先调用 `vault_status`，再调用 `agent_secret_usage_policy`。

## 6. Agent 敏感信息使用策略

这是连接 MCP 后的必做步骤。将 [SVLT 敏感信息使用策略](svlt-agent-policy-zh-CN.md) 中的代码块原样交给任何 Agent。

策略要求 Agent：

1. 将 App 选定的 v2 `敏感信息.md` 视为 SVLT managed catalog 的权威目录；每条数据属于 Index → Entry → Field，每个引用对应本地保险箱中的独立加密记录。
2. 仅通过 Catalog MCP/IPC 使用 `secret://...` 引用或允许返回的非敏感元数据，绝不直接读取、解析或修改 managed 文件。
3. 遵守 `svlt-catalog-schema-v2.md`：普通字段使用 `value`，秘密字段只使用 `secretRef`，禁止秘密明文。
4. 不得把笔记、历史、日志、缓存或模型记忆冒充为 SVLT Secret；环境变量、外部 provider 和用户当前明文属于其各自安全规则，不由 SVLT 接管。
5. 先判断用户是否选择 SVLT；选择后再检查 SVLT 状态并按具体动作使用 `secret_auto_handle_text`、`secret_action_router` 或更窄的 MCP 工具；`locked` 不是全局门禁。
6. 任务提到服务、设备、主机、账号或用途但没有凭据来源时，可以用 `secret_search` 按非敏感上下文自动发现引用；用户已明确选择 plaintext 或外部 provider 时不得搜索并替换来源。
7. 用 Index、Entry、alias、tag、endpoint 和允许返回的字段区分候选；同一目标下的不同 Entry 不得合并。`secret_search` 不返回源文件路径、行号或完整目录内容。
8. Catalog 写入必须使用 App 当前有效的 metadata/structure 编辑授权（最长 10 分钟）；MCP 不携带或伪造 lease/nonce。写入后调用 `secret_catalog_validate`。Obsidian 不得直接写 managed catalog。
9. 低风险绑定目标可静默执行；危险操作由同一请求等待本机审批。搜索静默不代表明文导出静默；SVLT 派生明文不得离开专用操作。用户明确选择 plaintext 或外部 provider 时，SVLT 的工具不可用、策略拒绝或 Catalog 命中不应单独阻断本次操作。

10. `USER_EXPLICIT_PLAINTEXT` 不要求 SVLT lookup、comparison、replacement、import 或 authorization。只有用户明确要求“存入 SVLT”或“使用 SVLT 中的那个”时，才进入 `SVLT_MANAGED_OPERATION`；当前选择覆盖上一轮的 SVLT 或 external provider 选择。

## 7. Agent 启动自检

Agent 接入后先做：

1. 调用 `vault_status`
2. 调用 `agent_secret_usage_policy`

预期：

- `vault_status` 返回 `available`、`ready` 和 `approvalPending`；`locked` 仅为兼容字段。
- `agent_secret_usage_policy` 返回可用工具和安全规则。

普通操作不要求 SVLT.app 一直运行。若通道不可达，先打开一次 SVLT 完成 SMAppService 注册/批准；如果状态中的 `locked` 为 true，仍应直接提交具体操作，让 Agent 本地策略决定是否需要认证。

## 8. 工具选择规则

| 场景 | 工具 | Agent 输入秘密的方式 |
| --- | --- | --- |
| 文本、笔记片段或工具输出里有 `secret://` | `secret_auto_handle_text` | 原文中保留引用 |
| 查看单个秘密给用户本人 | `secret_reveal_request` | `reference` |
| 本地显示整段解密文本 | `paragraph_reveal_request` | `references` + `template` |
| 导出填充后的敏感文本到本地文件 | `export_resolved_text_to_local_file` | `references` + `template` + `destinationPath` |
| SSH 到本机或内网设备 | `ssh_command_with_secret` | `passwordRef`，可选 `usernameRef` |
| 本地/内网 HTTP Basic Auth | `local_http_request_with_secret` | `passwordRef`，可选 `usernameRef` |
| API token 请求 | `api_request_with_token` | `tokenRef` |
| 数据库只读查询 | `database_query_with_secret` | `passwordRef`，可选 `usernameRef` |
| SFTP/SCP | `sftp_transfer_with_secret` | `passwordRef`，可选 `usernameRef` |
| 本地/内网页登录填充 | `browser_web_login_with_secret` | `passwordRef`，可选 `usernameRef` |
| 本地 App 表单填充 | `local_app_form_fill_with_secret` | 字段 `valueRef` |
| 自动路由本机动作 | `secret_action_router` | 按 intent 传引用 |

## 9. `secret_action_router` intent

`secret_action_router` 支持：

- `ssh_command`
- `local_http_request`
- `api_request`
- `database_query`
- `sftp_transfer`
- `browser_web_login`
- `local_app_form_fill`
- `export_resolved_text`

Agent 不确定用哪个具体工具时，优先使用 router；已经明确场景时，直接使用具体工具。

## 10. 常用输入示例

### 10.1 SSH

```json
{
  "host": "192.168.2.240",
  "username": "zyk",
  "passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS",
  "command": "hostname && whoami && uptime",
  "risk": "read"
}
```

### 10.2 API token

```json
{
  "url": "http://192.168.2.240:8080/api/status",
  "tokenRef": "secret://0123456789ABCDEFGHJKMNPQRS",
  "includeBodyPreview": true
}
```

不要把 token 放进 URL query、header 字符串或聊天。

### 10.3 数据库只读查询

```json
{
  "engine": "postgres",
  "host": "192.168.2.240",
  "database": "app",
  "username": "readonly_user",
  "passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS",
  "query": "select current_user",
  "maxRows": 20
}
```

只允许单条只读 SQL。不要执行 `insert`、`update`、`delete`、`drop`、`alter`、`copy` 等。

### 10.4 SFTP list

```json
{
  "operation": "list",
  "host": "192.168.2.240",
  "username": "zyk",
  "passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS",
  "remotePath": "/share"
}
```

路径必须明确，不能使用 `..`、glob 或 shell 字符。

### 10.5 本地网页登录填充

```json
{
  "url": "http://192.168.2.240/login",
  "username": "zyk",
  "passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS",
  "usernameSelector": "#user",
  "passwordSelector": "#password",
  "submitSelector": "button[type=submit]",
  "submit": true
}
```

如果返回 `SAFE_AUTOFILL_UNAVAILABLE`，说明 SVLT managed 路径当前没有安全浏览器 runner。不要把 SVLT 派生明文降级到普通工具或剪贴板；用户已经明确选择其他工具或当前明文时，由该工具和工作区规则处理。

## 11. 失败处理

| 状态 | Agent 应该怎么做 |
| --- | --- |
| `APP_UNAVAILABLE` | 让用户打开一次 SVLT 完成后台服务注册/批准后重试；不要要求 GUI 一直保持打开。 |
| `URL_NOT_ALLOWED` / `HOST_NOT_ALLOWED` | 目标不是 localhost、`.local`、私有 IP 或显式 allowlist。请用户确认目标。 |
| `URL_CREDENTIALS_NOT_ALLOWED` | URL 里包含用户名或密码。改用 `usernameRef` / `passwordRef`。 |
| `URL_TOKEN_NOT_ALLOWED` | URL query 里出现 token/key/password 等敏感参数。改用 `tokenRef`。 |
| `COMMAND_NOT_ALLOWED` | SSH 命令超出只读安全边界。换成更窄命令或新增专用工具。 |
| `QUERY_NOT_ALLOWED` | SQL 不是单条只读语句。改成只读查询。 |
| `PATH_NOT_ALLOWED` | SFTP/SCP 路径不安全。改成确定路径。 |
| `SAFE_AUTOFILL_UNAVAILABLE` | SVLT 管理路径的浏览器或本地 App 安全填充 runner 尚不可用；不要把 SVLT 派生明文降级到普通工具。用户已明确选择其他工具或当前明文时，由该工具自己的规则处理。 |
| `*_REQUEST_FAILED` | 报告非敏感失败状态，建议检查服务、网络、权限或 App 状态。 |

## 12. 验证安装是否成功

在 Agent 中发起：

```text
请调用 svlt 的 vault_status，并读取 agent_secret_usage_policy。
```

通过标准：

- Agent 不要求你粘贴密码。
- Agent 能看到 MCP 工具列表。
- Agent 能复述“secret:// 是不透明引用”。
- Agent 不返回任何明文秘密。

## 13. 安全注意事项

- 不要把 `secret://` 对应的明文写入知识库、issue、PR、聊天记录或日志。
- 不要把 bearer token、basic auth、cookie、session id 打印到工具结果。
- 不要把数据库敏感列返回聊天。
- 不要使用通用 shell、curl、剪贴板或浏览器自动填表绕过 MCP 安全工具。
- 对公网发送、删除、改密码、数据库写入等高风险动作，必须新增更窄的专用 allowlisted 工具。
