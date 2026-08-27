# Catalog v3 Obsidian 手工回归

这是一份不依赖 GUI 自动化工具的可重复手工回归清单，用于验证 SVLT Catalog v3 与真实 Obsidian Vault 的协作边界。它补充 parser、watcher 和 IPC 自动化测试；不能用自动化测试结果替代本清单中的真实应用验证。

## 测试准备

1. 使用专用测试 Vault，不要使用生产 Vault。
2. 先备份测试 Vault、SVLT 的 CatalogIntegrity sidecar 和 Keychain 测试数据。
3. 只使用明显的测试值；不要在测试记录、截图、终端或日志中输入真实密码。若需要 secret 字段，使用测试用 secret record 和 opaque `secret://` 引用。
4. 确认 SVLT App、MCP 服务和 `obsidian-plugin/svlt` 插件均为本次构建版本。
5. 记录测试文件的原始 Markdown，特别是普通空行、注释、callout、WikiLink 和未受管 Markdown。

## 流程

按顺序执行以下步骤，并在每一步记录预期结果：

1. 在专用 Vault 中创建一个新的 v3 `敏感信息.md`，通过 SVLT 完成初始化并确认校验状态为已验证。
2. 用 Obsidian 打开该文件，确认文档可以正常阅读和编辑。
3. 在 policy block 和受管 Catalog 结构之外添加普通 Markdown（例如说明段落或 callout）。保存后，确认 SVLT 不把它误认成 Catalog 语义变化，也不删除它。
4. 添加一个合法的 `[[WikiLink]]`，保存后确认链接仍存在且 Obsidian 可以解析。
5. 在一个普通受管字段中修改非敏感值，保存文件。
6. 等待 watcher 刷新或在 App 中刷新，确认 App 看到字段变化；格式变化本身不应触发高风险审批。
7. 在 App 中修改另一个普通字段并保存条目，确认修改可以写回 Markdown，且只修改对应 source range，不重排整份文档。
8. 回到 Obsidian，确认原有空行、注释、callout、WikiLink 和未受管 Markdown 仍保持原格式；再次保存并确认没有重复插入 marker 或 policy block。
9. 在 Obsidian 的链接面板或反向链接视图中确认 WikiLink/backlink 正常。
10. 在测试受管字段中把已有测试 secret 引用从一个合法 `secret://` 引用替换成另一个引用，保存后确认 App 出现 pending external change，并且未经本机批准不会接纳。
11. 确认 Obsidian 插件命令只有“验证 SVLT 敏感信息目录”和“查看 SVLT 目录诊断”，不再提供加密、临时解密或还原命令。
12. 制造一个格式错误（例如 heading 与 marker 标题不一致），确认插件状态栏显示问题数量、Notice 给出首个问题行号，诊断面板可以跳转到对应行；修复后错误自动消失。
13. 在 App 的具体密码字段点击“解密”，确认需要本机身份认证，明文只在 App 内短暂显示；关闭详情或让 App 进入后台后明文立即清除，且 Markdown、Catalog 搜索结果、Audit 和日志中没有明文。
14. 在 Obsidian 中将 `敏感信息.md` 重命名或移动到同一 Vault 的另一目录，重新打开文件并让 SVLT 校验；确认合法的、唯一匹配的已认证 sidecar 可以被安全重新绑定，且 Catalog 不要求无条件重新创建业务数据。若匹配不唯一，预期是 fail closed，而不是猜测绑定。
15. 退出并重新启动 SVLT App，确认文档、revision、secret 引用和完整性状态保持正确。
16. 退出并重新启动 Obsidian，重新打开文件并重复一次普通字段读取、WikiLink 检查和 Catalog validation，确认重启后工作流仍然成立。

## 通过标准

- 普通 Markdown 与 WikiLink 被保留；没有整文件 canonicalize 或无关重排；Obsidian 插件是只读校验器，不修改文件。
- 普通字段变化可以自动刷新；高风险 secret 引用变化必须进入 pending/本机批准路径。
- 插件不提供加密、解密或还原命令；字段解密只发生在 App 内。
- Reveal 只显示在 App 安全窗口，明文不进入 Markdown、搜索返回、Audit、日志或持久化测试产物。
- App 和 Obsidian 重启后 accepted state、revision、sidecar 和 Catalog 语义一致。
- rename/move 只在 exactly-one authenticated semantic match 时自动重新绑定；旧 path sidecar 的保留和歧义时的人工恢复属于当前保守策略。

## 证据记录

记录以下信息即可，不要记录真实密码：

- SVLT、MCP、Obsidian 插件版本或 commit SHA；
- 测试 Vault 和 Catalog 文件的非敏感路径；
- 每一步的通过/失败、时间和观察到的 revision；
- 发生审批时记录审批结果和 semantic diff 类型，不要截图或复制明文；
- rename/move 前后的 sidecar 文件名、validation 结果和是否出现人工恢复提示。

## Release 安装态 Secure Input E2E

在安装到正式位置的 release App 上，使用仓库脚本创建隔离 Catalog：

```bash
SVLT_RELEASE_APP=/Applications/SVLT.app ./scripts/release-e2e.sh
```

脚本会在 `test-artifacts/release-e2e/<run-id>/` 自动创建仅当前用户可读写的
Catalog，并先验证 App 与内置 `SVLTAgent` 的代码签名 Team ID。它不会创建模拟器、
写入真实凭据或自动操作 Touch ID。按脚本输出的步骤，在真实 macOS 用户会话中完成
一次测试输入、Touch ID/密码认证、同一 `requestID` 状态轮询，以及失焦/锁屏/睡眠取消
检查。记录时只保留状态、revision、时间和 semantic diff 类型；不要记录测试明文。

该脚本是手工 release E2E 的准备和证据边界，不是 CI 中的 GUI/Touch ID 替代品。

本清单需要真实 macOS Obsidian、Vault 和用户身份认证才能完成。CI/自动环境没有真实
Obsidian GUI 或 Touch ID，因此自动测试通过不代表本清单已经执行；合并前应将本文件
作为 manual verification gap 的明确记录。
