# SVLT MCP SSH 单行命令测试报告

## 测试信息

- 测试日期：2026-08-31
- 测试接口：`mcp__agent_secret_vault__ssh_command_with_secret`
- 测试范围：仅通过 SVLT MCP 验证 SSH 原始单行命令负载
- 命令负载：`printf 'SVLT_SSH_SINGLE_LINE_OK\n'`
- 命令性质：只读固定字符串回显，不读取文件、不修改远端状态
- 凭据处理：由 SVLT 在 MCP/Agent 边界内解析；本报告不记录主机、用户名或 `secret://` 引用

## 测试结果

结论：失败。SVLT MCP 请求已发出，但 SSH 命令未执行到远端。

SVLT 返回的外层结果为 `status=COMPLETED`、`exitCode=0`，但输出同时包含 SSH 参数解析错误，因此不能将该结果视为成功。

关键错误：

```text
command-line line 0: keyword controlpath extra arguments at end of line
expect: spawn id exp5 not open
```

预期的 `SVLT_SSH_SINGLE_LINE_OK` 未返回。

## 失败原因

SVLT 生成的 `/usr/bin/ssh` 调用包含 `ControlPath` 参数。该路径位于 macOS 的 `Application Support` 目录，其中包含空格；当前 SVLT 通过命令字符串启动 SSH 时没有正确保护这个参数，导致 OpenSSH 将路径拆分并报出：

```text
keyword controlpath extra arguments at end of line
```

SSH 在本地参数解析阶段即失败，未进入远程连接、认证或远程命令执行阶段。随后 `expect` 继续等待已关闭的进程，产生了次级错误：

```text
expect: spawn id exp5 not open
```

因此，根因是 SVLT SSH 执行器对包含空格的 `ControlPath` 参数传递不安全；`expect` 错误是连带现象。

## 验证边界

- `vault_status` 返回 `READY`，SVLT Agent 和本地策略引擎可用。
- SSH 请求通过 SVLT MCP 发起，未使用普通 `ssh` 命令或其他凭据通道。
- 错误发生在本地 SSH 参数解析阶段，未观察到远端命令输出。
- 本次未修改 SVLT 源码，也未对远端执行重试或其他命令。

## 最小修复建议

在 SVLT SSH 执行器中将 SSH 参数作为独立的 argv 传递，确保 `ControlPath` 的完整路径不会因空格被拆分。若必须通过 `expect spawn` 使用命令字符串，则应使用 Tcl 安全的参数列表/引用方式；不要依赖未转义的拼接字符串。

修复后应重新执行同一条固定单行负载，并同时检查：

1. 返回 `SVLT_SSH_SINGLE_LINE_OK`。
2. 外层 `status`、`exitCode` 与实际 SSH 成功状态一致。
3. 不再出现 `controlpath extra arguments` 或 `spawn id ... not open`。
