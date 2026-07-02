# Agent Secret Vault 中文使用教程

本文面向普通用户和本地 Agent 使用者。正常使用不需要 Xcode，不需要打开源码项目。

## 1. 这个 App 做什么

Agent Secret Vault 用来把知识库、笔记和对话里的敏感信息替换成 `secret://...` 引用。

正确效果：

- 知识库里保存 `secret://...`，不保存明文密码、token、cookie、私钥。
- Codex、Claude、Hermes 等 Agent 在对话中只看到引用。
- 需要本机使用秘密时，Agent 通过本机 MCP 工具请求 App 解密。
- 明文不返回聊天，只在本机 App、MCP 内部或受控本地动作中短暂使用。

## 2. 普通用户安装

先安装 Node.js 24 或更新版本。MCP server 需要 Node.js 运行。

然后：

1. 下载并解压 `AgentSecretVault-release.zip`。
2. 双击 `install.command`。
3. 如果 macOS 拦截，右键点击 `install.command`，选择“打开”。
4. 安装完成后，脚本会自动打开 Agent Secret Vault。

安装后文件位置：

- App：`/Applications/AgentSecretVault.app` 或 `~/Applications/AgentSecretVault.app`
- MCP server：`~/Library/Application Support/AgentSecretVault/MCP`
- MCP 配置：`~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json`
- Obsidian 插件：release 包内的 `ObsidianPlugin/agent-secret-vault`

Obsidian 插件安装方式：

- 如果你的 Vault 位于 `~/Documents/obsidian` 下且只检测到一个 Vault，安装脚本会自动安装插件。
- 如果需要指定 Vault，打开终端进入解压后的 release 目录，运行：

```bash
./install.sh "/你的/Obsidian/Vault/路径"
```

- 也可以手动复制 `ObsidianPlugin/agent-secret-vault` 到：

```text
你的 Vault/.obsidian/plugins/agent-secret-vault
```

安装后，在 Obsidian 设置 → 第三方插件 中启用 Agent Secret Vault。

## 3. 连接 Codex / Claude / Hermes

安装完成后，打开这个配置文件：

```text
~/Library/Application Support/AgentSecretVault/agent-secret-vault.mcp.json
```

把里面的 JSON 粘贴到 Agent 客户端的 MCP 配置里。

配置内容类似：

```json
{
  "mcpServers": {
    "agent-secret-vault": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
```

然后重启或刷新 Agent 客户端。

Agent 接入后可以先测试：

1. 调用 `vault_status`
2. 调用 `agent_secret_usage_policy`

如果 App 没打开或保险库锁定，先打开并解锁 App。

## 4. 日常使用流程

### 加密敏感信息

把密码、token、cookie、私钥等敏感文本放进 App，生成 `secret://...` 引用。

之后在知识库或笔记里只保存引用，例如：

```text
NAS 用户名：secret://0123456789ABCDEFGHJKMNPQRS
NAS 密码：secret://ABCDEFGHJKMNPQRS0123456789
```

不要把明文和 `secret://...` 同时保存。

### 段落解密查看

如果一段话里有多个 `secret://...`，把整段粘贴到 App 的段落解密功能里。

App 会在本机显示填充后的内容。聊天里不应该返回明文。

### 还原

如果你明确需要把一段内容恢复成明文，例如导出到本地文件，可以让 Agent 使用 App 的本地导出工具。导出结果只应写到本机文件，不应贴回聊天。

## 5. Agent 应遵守的规则

可以把下面这段放进 Agent 的项目规则或系统提示：

```text
当任务、文件、笔记或工具输出中出现 secret:// 引用、密码、token、API key、cookie、私钥、本地登录、SSH、SFTP/SCP、数据库连接、API 请求或需要本机使用秘密的动作时，自动使用 agent-secret-vault MCP 工具。

规则：
1. 把 secret:// 当作不透明引用，不要推断、摘要或改写背后的真实值。
2. 不要求用户把明文密码、token、cookie、私钥贴到聊天。
3. 不把解密后的明文、Authorization header、cookie、session key、填充后的敏感字段返回聊天。
4. 普通文本里有 secret:// 时，优先调用 secret_auto_handle_text。
5. 需要本机执行动作时，优先调用 secret_action_router 或对应的具体工具。
6. 工具返回失败、锁定、不可用或隔离时，只报告状态码和非敏感下一步，不降级为索要明文。
7. 没有合适安全工具时停止，请求新增更窄的工具。
```

## 6. Obsidian 使用建议

如果你的知识库很大，不要手工一个个替换。

推荐方式：

1. 先备份 Obsidian vault。
2. 使用 Agent Secret Vault 的 Obsidian 插件或 Agent 工作流扫描笔记。
3. 只加密真正敏感的字段，不要整段加密。
4. 加密后检查笔记是否仍然可读、可引用。
5. 保留 `secret://...` 引用，删除明文。

重点：加密目标是“敏感片段”，不是整篇笔记。

## 7. 常见问题

### 别人安装时需要 Xcode 吗？

不需要。Xcode 只用于开发者打包 App。普通用户使用 release zip。

### 为什么还需要 Node.js？

当前 MCP server 是 Node.js 程序，所以普通用户需要 Node.js 24 或更新版本。后续如果做成完全原生 helper，可以去掉这个要求。

### macOS 提示无法打开怎么办？

右键点击 `install.command` 或 App，选择“打开”。这是因为当前版本不是 Apple Developer ID 公证包。

### Agent 能不能看到明文？

设计目标是聊天里不返回明文。Agent 需要本机使用秘密时，应通过 MCP 工具让 App 在本机内部解密和使用。

### 知识库里已经有很多明文怎么办？

先备份，再扫描。只替换密码、token、key、cookie、私钥等敏感片段，不要把整段知识加密。
