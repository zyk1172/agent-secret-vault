# SVLT 中文使用教程

本文面向普通用户和本地 Agent 使用者。正常使用不需要 Xcode，不需要打开源码项目。

## 1. 这个 App 做什么

SVLT 用来把知识库、笔记和对话里的敏感信息替换成 `secret://...` 引用。

正确效果：

- 知识库里保存 `secret://...`，不保存明文密码、token、cookie、私钥。
- Codex、Claude、Hermes 等 Agent 在对话中只看到引用。
- 需要本机使用秘密时，Agent 通过本机 MCP 工具请求 App 解密。
- 明文不返回聊天，只在本机 App、MCP 内部或受控本地动作中短暂使用。
- SVLT.app 只负责界面和设置；SVLTAgent 是由 launchd 管理的独立后台服务，App 退出后仍可连接。

## 2. 普通用户安装

先安装 Node.js 24 或更新版本。MCP server 需要 Node.js 运行。

然后：

1. 下载并解压 `SVLT-release.zip`。
2. 双击 `install.command`。
3. 如果 macOS 拦截，右键点击 `install.command`，选择“打开”。
4. 安装完成后，脚本会自动打开 SVLT。

安装后文件位置：

- App 与后台 Agent：`/Applications/SVLT.app` 或 `~/Applications/SVLT.app`
- LaunchAgent：`SVLT.app/Contents/Library/LaunchAgents/com.agent-secret-vault.SVLT.agent.plist`
- MCP server：`~/Library/Application Support/AgentSecretVault/MCP`
- MCP 配置：`~/Library/Application Support/AgentSecretVault/svlt.mcp.json`
- Obsidian 插件：release 包内的 `ObsidianPlugin/svlt`

Obsidian 插件安装方式：

- 如果你的 Vault 位于 `~/Documents/obsidian` 下且只检测到一个 Vault，安装脚本会自动安装插件。
- 如果需要指定 Vault，打开终端进入解压后的 release 目录，运行：

```bash
./install.sh "/你的/Obsidian/Vault/路径"
```

- 也可以手动复制 `ObsidianPlugin/svlt` 到：

```text
你的 Vault/.obsidian/plugins/svlt
```

安装后，在 Obsidian 设置 → 第三方插件 中启用 SVLT。

## 3. 连接 Codex / Claude / Hermes

首次打开 SVLT 时，App 会通过 `SMAppService.agent` 注册后台 Agent。若 macOS 要求批准，请到“系统设置 → 通用 → 登录项”批准 SVLT。不要手动把 plist 复制到 `~/Library/LaunchAgents`。

安装完成后，打开这个配置文件：

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

把里面的 JSON 粘贴到 Agent 客户端的 MCP 配置里。

配置内容类似：

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

然后重启或刷新 Agent 客户端。

接着，把 [SVLT 敏感信息使用策略](svlt-agent-policy-zh-CN.md) 中的代码块原样放进 Codex、Claude、Hermes、OpenClaw 或其他 Agent 的系统提示、项目规则或工作区规则。这是连接 MCP 后的必做步骤：它要求 Agent 优先使用 App 选定的 `敏感信息.md` 和 `secret://...` 引用，不得直接读取索引或从笔记、日志、环境变量、历史对话、缓存和模型记忆中绕过获取敏感值。

Agent 接入后可以先测试：

1. 调用 `vault_status`
2. 调用 `agent_secret_usage_policy`

普通状态、元数据、加密和受控 MCP 操作不要求 SVLT.app 一直打开。Agent 启动时可以报告兼容字段 `locked`，但它不再是 Agent 的全局门禁；具体操作由本地策略决定静默、审批或拒绝。睡眠、锁屏、用户会话切换或手动锁定后会清除内存中的运行时授权，下一次操作按需重新获取。真正需要图形界面的 reveal 会通过 Agent → App UI 请求桥按需激活 App。

## 4. 日常使用流程

### 加密敏感信息

在 App 的“敏感信息”中选择或新建 `敏感信息.md`。它是 SVLT 管理的唯一权威目录：使用 Index → Entry → Field 结构保存服务、地址、账号、用途等允许暴露的非敏感上下文，并用 `secret://...` 引用对应本地保险箱中的独立加密记录。v2 managed 文件只能由 Catalog Store 写入。

需要批量检查时，在 App 的“本地扫描”中选择单个 Markdown 文件或文件夹。规则只在本机运行，候选默认不选中；确认后只把原笔记中的命中值替换为无符号包裹的引用。managed `敏感信息.md` 不会被本地扫描直接写入，目录记录请使用结构化编辑器或 Catalog MCP。

笔记中只保存引用，例如：

```text
NAS 用户名: secret://0123456789ABCDEFGHJKMNPQRS
NAS 密码: secret://ABCDEFGHJKMNPQRS0123456789
```

不要把明文和 `secret://...` 同时保存。

### 段落解密查看

如果一段话里有多个 `secret://...`，把整段粘贴到 App 的段落解密功能里。

App 会在本机显示填充后的内容。聊天里不应该返回明文。

### 还原

如果你明确需要把一段内容恢复成明文，例如导出到本地文件，可以让 Agent 使用 App 的本地导出工具。导出结果只应写到本机文件，不应贴回聊天。

## 5. Agent 应遵守的规则

将 [SVLT 敏感信息使用策略](svlt-agent-policy-zh-CN.md) 中的代码块原样放进 Agent 的系统提示、项目规则或工作区规则。策略要求 Agent 只经 MCP 使用 `敏感信息.md` 中的独立密文记录和 `secret://...` 引用；不能直接读取或修改索引，也不能从笔记、日志、缓存、环境变量或模型记忆绕过获取敏感值。

## 6. Obsidian 使用建议

如果你的知识库很大，不要手工一个个替换。

推荐方式：

1. 先备份 Obsidian vault。
2. 在 App 的“本地扫描”中选择笔记文件夹，先看清候选和完整段落，再决定是否加密。
3. 只加密真正敏感的字段，不要整段加密。
4. Obsidian 仅保留手动兜底：选中文字后使用“加密选中文本”。
5. 加密后检查笔记是否只留下前置一个英文空格的 `secret://` 引用，没有链接、反引号或方括号包裹。
6. 保留 `secret://...` 引用，删除明文。

重点：加密目标是“敏感片段”，不是整篇笔记。

## 7. 常见问题

### 别人安装时需要 Xcode 吗？

不需要。Xcode 只用于开发者打包 App。普通用户使用 release zip。

### 为什么还需要 Node.js？

当前 MCP server 是 Node.js 程序，所以普通用户需要 Node.js 24 或更新版本。后续如果做成完全原生 helper，可以去掉这个要求。

### macOS 提示无法打开怎么办？

右键点击 `install.command` 或 App，选择“打开”。这是因为当前版本不是 Apple Developer ID 公证包。

### Agent 能不能看到明文？

MCP、Codex 和 Obsidian 的协议不会返回明文。Agent 只在内存中为受控本地动作或 App-owned reveal session 暂时解析；普通 reveal 通过 UI 请求桥交给 SVLT.app 显示。

### 如何确认后台占用？

release 包中包含 `check-agent-resources.sh`：

```bash
./check-agent-resources.sh
```

也可以使用 `ps`、`top`，必要时使用 `powermetrics`。后台 Agent 主要阻塞等待 Unix Socket，没有 heartbeat、Timer、周期性 MCP ping 或全量扫描。

### 知识库里已经有很多明文怎么办？

先备份，再在 App 中审核候选。只替换密码、token、key、cookie、私钥等敏感片段，不要把整段知识加密。
