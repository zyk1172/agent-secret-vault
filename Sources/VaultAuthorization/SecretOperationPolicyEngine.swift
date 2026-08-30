import Foundation
import VaultCore

/// SVLT policy classifies authorization requirements; it does not replace
/// the device owner's decision.
///
/// Semantic risk may promote an operation from silent to reusable to fresh
/// approval, and it may attach warning text for the approval prompt, but it
/// must not hard-deny an otherwise technically executable request.
///
/// Hard failures are reserved for malformed, contradictory, stale, or
/// identity-invalid requests (`PolicyDecision.technicalFailure`). The device
/// owner makes the final allow/deny decision through Touch ID / password for
/// everything else.
public struct SecretOperationPolicyEngine: Sendable {
    public struct Configuration: Sendable {
        public let maxCommandLength: Int
        public let safeDownloadDirectory: URL

        public init(
            maxCommandLength: Int = 65_536,
            safeDownloadDirectory: URL? = nil
        ) {
            self.maxCommandLength = maxCommandLength
            self.safeDownloadDirectory = (safeDownloadDirectory
                ?? FileManager.default.homeDirectoryForCurrentUser
                    .appendingPathComponent("Library/Application Support/AgentSecretVault/Downloads", isDirectory: true))
                .standardizedFileURL
        }
    }

    private let configuration: Configuration
    private let sshCommandClassifier: SSHCommandRiskClassifier

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
        self.sshCommandClassifier = SSHCommandRiskClassifier(maxCommandLength: configuration.maxCommandLength)
    }

    public func evaluate(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata]
    ) -> PolicyDecision {
        let normalizedDestination = descriptor.normalizedDestination
        let local = localDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination
        )
        let agentRisk = descriptor.agentAssessment.declaredRisk
        let effectiveRequirement = Self.effectiveAuthorizationRequirement(
            local: local.authorizationRequirement,
            agentRisk: agentRisk
        )
        let effectiveRisk: OperationRisk = {
            switch effectiveRequirement {
            case .none: return .silent
            case .reusableApproval, .freshApprovalRequired: return .approvalRequired
            case .denied: return .denied
            }
        }()

        var reasons = local.reasons
        if agentRisk != .silent {
            if agentRisk == .denied {
                reasons.append("⚠️ Agent 自身认为此操作风险很高；最终是否执行由设备所有者决定")
            } else {
                reasons.append("Agent 提示此操作需要审批（\(agentRisk.rawValue)）")
            }
            let agentReason = descriptor.agentAssessment.reason
            if !agentReason.isEmpty {
                reasons.append("Agent 原因：\(agentReason)")
            }
        }

        return PolicyDecision(
            risk: effectiveRisk,
            reasons: reasons.map(Self.sanitizeReason),
            normalizedDestination: normalizedDestination,
            requiredApproval: effectiveRequirement.requiresApproval,
            policyRuleID: local.policyRuleID,
            authorizationRequirement: effectiveRequirement,
            requiresFreshApprovalOnFirstUse: false,
            technicalFailure: local.technicalFailure
        )
    }

    /// The Agent's declared risk is a bounded hint, not authorization. It can
    /// raise the local decision, but it must not reshape the lease semantics
    /// the local policy already granted, and it must not deny the request on
    /// the device owner's behalf: an Agent "denied" hint becomes a fresh
    /// approval with a visible warning, never a refusal.
    private static func effectiveAuthorizationRequirement(
        local: AuthorizationRequirement,
        agentRisk: OperationRisk
    ) -> AuthorizationRequirement {
        switch agentRisk {
        case .silent:
            return local
        case .denied:
            switch local {
            case .denied:
                return .denied
            case .none, .reusableApproval:
                return .freshApprovalRequired
            case .freshApprovalRequired:
                return .freshApprovalRequired
            }
        case .approvalRequired:
            switch local {
            case .none:
                // The local policy found no side effects, but the Agent
                // believes there are. Demand a fresh decision instead of
                // trusting the Agent to define the lease terms.
                return .freshApprovalRequired
            case .reusableApproval, .freshApprovalRequired:
                // The local policy already set the requirement; agreeing
                // that approval is needed cannot raise reusable to fresh.
                return local
            case .denied:
                return .denied
            }
        }
    }

    private func localDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        normalizedDestination: String?
    ) -> PolicyDecision {
        if let invalidShape = invalidOperationShape(descriptor) {
            return decision(.denied, [invalidShape.reason], invalidShape.ruleID, normalizedDestination, technicalFailure: true)
        }

        let localRisk: OperationRisk
        let localRequirement: AuthorizationRequirement
        var reasons: [String]
        let ruleID: String

        switch descriptor.actionType {
        case .vaultStatus, .usagePolicy, .inspectReference, .checkReferenceExists:
            return decision(.silent, ["状态或非敏感元数据操作"], "metadata.silent", normalizedDestination)
        case .revealPlaintext, .copyPlaintext, .exportPlaintext,
             .deleteSecret, .changeSecretPolicy, .changeDestinationBinding,
             .changeAllowlist, .changeAuthorizationRules, .changeKeychain,
             .migrateMasterKey, .importRecoveryKey, .exportRecoveryKey,
             .restoreVault, .clearVault, .batchDelete, .resetVault:
            localRisk = .approvalRequired
            reasons = ["明文暴露、数据删除或安全设置变更，每次都需要设备所有者重新认证"]
            ruleID = "sensitive-control.fresh-approval"
            localRequirement = descriptor.actionType == .exportPlaintext
                ? .reusableApproval
                : .freshApprovalRequired
        case .sshCommand:
            let commandDecision = descriptor.sshCommandBatch == nil
                ? sshCommandClassifier.classify(command: descriptor.command)
                : sshCommandClassifier.classify(batch: descriptor.sshCommandBatch)
            localRisk = commandDecision.risk
            reasons = commandDecision.reasons
            ruleID = commandDecision.ruleID
            localRequirement = commandDecision.authorizationRequirement
        case .httpRequest, .apiRequest:
            let httpOutcome = httpDecision(descriptor)
            localRisk = httpOutcome.risk
            reasons = httpOutcome.reasons
            ruleID = httpOutcome.ruleID
            localRequirement = httpOutcome.requirement
        case .databaseQuery:
            let databaseOutcome = databaseDecision(descriptor.effectiveDatabaseStatement)
            localRisk = databaseOutcome.risk
            reasons = databaseOutcome.reasons
            ruleID = databaseOutcome.ruleID
            localRequirement = databaseOutcome.requirement
        case .sftpTransfer:
            let transferOutcome = sftpDecision(descriptor)
            localRisk = transferOutcome.risk
            reasons = transferOutcome.reasons
            ruleID = transferOutcome.ruleID
            localRequirement = transferOutcome.requirement
        case .browserLogin, .localAppFill:
            localRisk = .silent
            reasons = ["绑定目标上的普通登录或表单填充"]
            ruleID = "bound-login.silent"
            localRequirement = .none
        case .localExecution:
            localRisk = .approvalRequired
            reasons = [
                "⚠️ 此操作会把凭据交给本地任意进程；该进程可能读取、保存、转换或传输凭据",
                "批准后 SVLT 无法保证 Agent 不获得该凭据；本次释放会被审计记录为 userApprovedSecretRelease"
            ]
            ruleID = "local-execution.user-approved-secret-release"
            localRequirement = .freshApprovalRequired
        case .trustedProcess:
            localRisk = .approvalRequired
            reasons = ["Trusted Process 会把 Secret 交给预先登记的签名进程；每次都需要设备所有者重新认证"]
            ruleID = "trusted-process.fresh-approval"
            localRequirement = .freshApprovalRequired
        }

        // A technical failure means the request itself is malformed or cannot
        // be verified; binding checks are meaningless for it.
        if localRisk == .denied || localRequirement == .denied {
            return decision(
                .denied,
                reasons,
                ruleID,
                normalizedDestination,
                technicalFailure: true
            )
        }

        let binding = bindingDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination
        )
        let effectiveRequirement = AuthorizationRequirement.max(
            localRequirement,
            binding.requirement
        )
        if effectiveRequirement == .denied {
            // Binding verification can only fail hard for technical reasons
            // (missing or contradictory credential identity information).
            return decision(
                .denied,
                reasons + binding.reasons,
                binding.ruleID,
                normalizedDestination,
                technicalFailure: true
            )
        }
        let effectiveRisk: OperationRisk = {
            switch effectiveRequirement {
            case .none: return .silent
            case .reusableApproval, .freshApprovalRequired: return .approvalRequired
            case .denied: return .denied
            }
        }()
        // When the binding check contributed nothing (bound destination, no
        // mismatch), the semantic rule that classified the operation stays the
        // reported rule ID; a binding promotion reports its own.
        let finalRuleID = binding.requirement == .none ? ruleID : binding.ruleID
        return decision(
            effectiveRisk,
            reasons + binding.reasons,
            finalRuleID,
            normalizedDestination,
            authorizationRequirement: effectiveRequirement
        )
    }

    private func invalidOperationShape(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        guard Set(descriptor.secretReferences).count == descriptor.secretReferences.count else {
            return ("操作不能重复使用同一个 secret:// 引用", "secret-reference.duplicate")
        }
        if let port = descriptor.port, !(1...65_535).contains(port) {
            return ("端口不在有效范围内", "operation.port.invalid")
        }

        if let payloadError = invalidTypedPayload(descriptor) {
            return payloadError
        }

        switch descriptor.actionType {
        case .sshCommand:
            guard descriptor.protocolType == .ssh else {
                return ("SSH 操作必须声明 ssh 协议", "ssh.protocol.invalid")
            }
            guard !(descriptor.command != nil && descriptor.sshCommandBatch != nil) else {
                return ("SSH 操作不能同时提供单条命令和批处理", "ssh.command-forms.ambiguous")
            }
            if let batch = descriptor.sshCommandBatch {
                guard (try? batch.validate()) != nil else {
                    return ("SSH 批处理参数无效", "ssh.batch.invalid")
                }
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("SSH 操作缺少目标主机", "ssh.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "ssh.port-mismatch")
            }
        case .httpRequest, .apiRequest:
            guard let rawURL = descriptor.url,
                  let url = URL(string: rawURL),
                  let scheme = url.scheme?.lowercased(),
                  let host = url.host,
                  !host.isEmpty,
                  scheme == "http" || scheme == "https" else {
                return ("HTTP 操作缺少有效目标 URL", "http.url.invalid")
            }
            let expectedProtocol: SecretOperationProtocol = scheme == "https" ? .https : .http
            guard descriptor.protocolType == expectedProtocol else {
                return ("操作协议与 URL scheme 不一致", "http.protocol-mismatch")
            }
            let effectivePort = url.port ?? (scheme == "https" ? 443 : 80)
            if let declaredPort = descriptor.port, declaredPort != effectivePort {
                return ("操作端口与 URL 实际端口不一致", "http.port-mismatch")
            }
            let actualDestination = SecretOperationDescriptor.normalizeDestination(rawURL)
            if let destination = descriptor.destination,
               SecretOperationDescriptor.normalizeDestination(destination) != actualDestination {
                return ("操作目标与 URL 主机不一致", "http.destination-mismatch")
            }
        case .browserLogin:
            guard descriptor.protocolType == .browser,
                  let rawURL = descriptor.url,
                  let url = URL(string: rawURL),
                  let scheme = url.scheme?.lowercased(),
                  let host = url.host,
                  !host.isEmpty,
                  scheme == "http" || scheme == "https",
                  url.user == nil,
                  url.password == nil else {
                return ("浏览器登录目标无效", "browser.url.invalid")
            }
        case .databaseQuery:
            guard descriptor.protocolType == .postgres || descriptor.protocolType == .mysql else {
                return ("数据库操作必须声明 postgres 或 mysql 协议", "database.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("数据库操作缺少目标主机", "database.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "database.port-mismatch")
            }
        case .sftpTransfer:
            guard descriptor.protocolType == .sftp || descriptor.protocolType == .scp else {
                return ("文件传输必须声明 sftp 或 scp 协议", "sftp.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("文件传输缺少目标主机", "sftp.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "sftp.port-mismatch")
            }
        case .localAppFill:
            guard descriptor.protocolType == .localApp else {
                return ("本地 App 填充必须声明 localApp 协议", "local-app.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("本地 App 填充缺少目标", "local-app.destination.missing")
            }
        default:
            break
        }

        return nil
    }

    private func invalidTypedPayload(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        guard let payload = descriptor.payload else { return nil }

        guard referencesMatch(
            payload.referencedSecretReferences,
            descriptor.secretReferences
        ) else {
            return ("typed payload 使用了未声明的 secret:// 引用", "operation.payload.reference-mismatch")
        }

        switch payload {
        case let .http(operation):
            guard (descriptor.actionType == .httpRequest || descriptor.actionType == .apiRequest),
                  descriptor.httpMethod == nil || descriptor.httpMethod?.uppercased() == operation.method.rawValue
            else {
                return ("HTTP payload 只能用于 HTTP/API 操作", "operation.payload.action-mismatch")
            }
        case let .database(operation):
            guard descriptor.actionType == .databaseQuery,
                  descriptor.protocolType == operation.engine,
                  !operation.database.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil),
                  descriptor.databaseStatement == nil || descriptor.databaseStatement == operation.statement,
                  (1...10_000).contains(operation.maxRows)
            else {
                return ("数据库 typed payload 与操作声明不一致", "database.payload.invalid")
            }
            guard operation.parameters.count <= 64,
                  operation.parameters.allSatisfy({ parameter in
                      !parameter.name.isEmpty
                          && parameter.name.utf8.count <= 128
                          && parameter.name.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7F }
                  }),
                  Set(operation.parameters.map(\.name)).count == operation.parameters.count else {
                return ("数据库参数定义无效", "database.parameters.invalid")
            }
        case let .fileTransfer(operation):
            guard descriptor.actionType == .sftpTransfer,
                  descriptor.protocolType == operation.protocolType,
                  !operation.remotePath.isEmpty,
                  operation.remotePath.utf8.count <= 4_096,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil),
                  descriptor.fileOperation == nil || descriptor.fileOperation == operation.operation,
                  descriptor.fileTarget == nil || descriptor.fileTarget == operation.localPath
            else {
                return ("文件传输 typed payload 与操作声明不一致", "sftp.payload.invalid")
            }
        case let .browser(operation):
            guard descriptor.actionType == .browserLogin,
                  descriptor.protocolType == .browser,
                  let payloadURL = operation.url,
                  !payloadURL.isEmpty,
                  descriptor.url == payloadURL,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil)
            else {
                return ("浏览器登录 typed payload 无效", "browser.payload.invalid")
            }
        case let .localApp(operation):
            guard descriptor.actionType == .localAppFill,
                  descriptor.protocolType == .localApp,
                  !operation.bundleID.isEmpty,
                  operation.fields.count <= 64,
                  descriptor.localAppBundleID == nil || descriptor.localAppBundleID == operation.bundleID,
                  operation.fields.allSatisfy({ field in
                      (field.value != nil) != (field.valueReference != nil)
                          && !field.name.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F }
                  })
            else {
                return ("本地 App typed payload 无效", "local-app.payload.invalid")
            }
        case let .export(operation):
            guard descriptor.actionType == .exportPlaintext, !operation.overwrite else {
                return ("导出 typed payload 不允许覆盖目标文件", "export.payload.invalid")
            }
        case let .trustedProcess(operation):
            guard descriptor.actionType == .trustedProcess,
                  !operation.profileID.isEmpty,
                  operation.arguments.count <= 32
            else {
                return ("trusted process typed payload 无效", "trusted-process.payload.invalid")
            }
        }

        return nil
    }

    /// Destination/protocol/policy bindings no longer refuse anything: a
    /// mismatch only promotes the operation to a fresh approval with the
    /// mismatch facts shown, and the device owner decides for this execution.
    /// Approving never mutates the saved binding.
    private func bindingDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        normalizedDestination: String?
    ) -> (requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard actionNeedsSecret(descriptor.actionType) else {
            return (.none, [], "no-secret.required")
        }

        guard !descriptor.secretReferences.isEmpty else {
            return (.denied, ["需要 Secret 的操作没有提供 secret:// 引用"], "secret-reference.missing")
        }

        var metadataByReference: [SecretReference: SecretPolicyMetadata] = [:]
        for item in metadata {
            guard metadataByReference[item.reference] == nil else {
                return (.denied, ["Secret 元数据包含重复引用，无法确认凭据身份"], "secret-metadata.duplicate")
            }
            metadataByReference[item.reference] = item
        }

        var requirement = AuthorizationRequirement.none
        var reasons: [String] = []
        for reference in descriptor.secretReferences {
            guard let secret = metadataByReference[reference] else {
                return (.denied, ["Secret 元数据缺失，无法确认凭据身份"], "secret-metadata.missing")
            }

            if let protocolType = descriptor.protocolType,
               !secret.allowedProtocols.isEmpty,
               !isAllowedProtocol(protocolType, for: descriptor, allowedProtocols: secret.allowedProtocols) {
                requirement = .freshApprovalRequired
                reasons.append(
                    "凭据未绑定当前协议（已保存：\(secret.allowedProtocols.joined(separator: "/"))；本次：\(protocolType.rawValue)），设备所有者确认后本次执行"
                )
            }

            if !isAllowedSecretPolicy(secret.policy, action: descriptor.actionType) {
                requirement = .freshApprovalRequired
                reasons.append(
                    "凭据被用户标记为 \(secret.policy.rawValue)；本次副作用需要设备所有者确认"
                )
            }

            guard let normalizedDestination else {
                continue
            }

            let exactBinding = secret.allowedDestinations.contains {
                SecretOperationDescriptor.normalizeDestination($0) == normalizedDestination
            }
            if exactBinding {
                continue
            }

            // The export root is the validated security boundary, not a
            // credential destination: an export lease stays on the ordinary
            // five-minute window (a standing product decision), so a
            // destination mismatch only asks for the ordinary approval.
            if descriptor.actionType == .exportPlaintext {
                if requirement == .none {
                    requirement = .reusableApproval
                    reasons.append("导出根目录不在凭据绑定中；导出授权按现有 5 分钟窗口执行")
                }
                continue
            }

            requirement = .freshApprovalRequired
            if isPublicDestination(normalizedDestination) {
                reasons.append("目标 \(normalizedDestination) 不在该凭据已保存的绑定中，且是公网地址；设备所有者确认后本次执行")
            } else {
                reasons.append("目标 \(normalizedDestination) 不在该凭据已保存的绑定中；设备所有者确认后本次执行")
            }
        }

        if requirement == .none {
            return (.none, [], "destination.bound")
        }
        return (requirement, reasons, "destination.owner-confirmation")
    }

    private func httpDecision(
        _ descriptor: SecretOperationDescriptor
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard let url = descriptor.url,
              let parsedURL = URL(string: url),
              parsedURL.user == nil,
              parsedURL.password == nil,
              parsedURL.host != nil,
              (parsedURL.scheme?.lowercased() == "http" || parsedURL.scheme?.lowercased() == "https")
        else {
            return (.denied, .denied, ["HTTP URL 无效或包含 URL 内嵌凭据"], "http.url.invalid")
        }

        let method = (descriptor.effectiveHTTPMethod ?? "GET").uppercased()
        let carriesSecret = !descriptor.secretReferences.isEmpty

        if hasCredentialQueryParameter(parsedURL) {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["URL query 携带凭据类参数，可能被记录在服务器日志或代理中；设备所有者确认后执行"],
                "http.credential-query.fresh-approval"
            )
        }

        if parsedURL.scheme?.lowercased() == "http", carriesSecret {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["目标使用未加密 HTTP，凭据可能以明文在网络中传输；设备所有者确认后执行"],
                "http.insecure-transport.fresh-approval"
            )
        }

        switch method {
        case "GET", "HEAD":
            return (.silent, .none, ["HTTP GET/HEAD 被本地解析为无副作用读取"], "http.read-only.silent")
        case "DELETE":
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["HTTP DELETE 可能删除远端资源，每次都需要设备所有者重新认证"],
                "http.delete.fresh-approval"
            )
        default:
            return (
                .approvalRequired,
                .reusableApproval,
                ["HTTP 请求可能产生副作用，首次需要本机审批，之后可在执行窗口内复用"],
                "http.write.reusable-approval"
            )
        }
    }

    private func databaseDecision(
        _ query: String?
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard let query, !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return (.denied, .denied, ["数据库查询为空"], "database.query.missing")
        }
        if isClearlyDestructiveSQL(query) {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["数据库查询包含明确的破坏性语义，每次都需要设备所有者重新认证"],
                "database.destructive.fresh-approval"
            )
        }
        if isReadOnlyDatabaseQuery(query) {
            return (.silent, .none, ["数据库查询被本地解析为只读语句"], "database.read-only.silent")
        }
        return (
            .approvalRequired,
            .reusableApproval,
            ["数据库查询可能改变数据库状态，首次需要本机审批，之后可在执行窗口内复用"],
            "database.write.reusable-approval"
        )
    }

    /// Only locally provable destructive SQL promotes to fresh. Unknown or
    /// unparseable SQL stays on the ordinary path — the device owner decides,
    /// not the parser.
    private func isClearlyDestructiveSQL(_ query: String) -> Bool {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if normalized.range(of: #"(?i)\b(drop|truncate|alter)\b"#, options: .regularExpression) != nil {
            return true
        }
        let firstKeyword = normalized.range(
            of: #"(?i)^\s*(delete|update)\b"#,
            options: .regularExpression
        )
        guard firstKeyword != nil else { return false }
        return normalized.range(of: #"(?i)\bwhere\b"#, options: .regularExpression) == nil
    }

    private func isReadOnlyDatabaseQuery(_ query: String) -> Bool {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return false }
        let withoutTrailingSemicolon = normalized.hasSuffix(";")
            ? String(normalized.dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
            : normalized
        // Only a single statement can be proven read-only locally; anything
        // else takes the ordinary approval path.
        guard !withoutTrailingSemicolon.contains(";") else { return false }
        guard withoutTrailingSemicolon.range(
            of: #"(?i)^\s*(select|with|show|describe|explain)\b"#,
            options: .regularExpression
        ) != nil else {
            return false
        }
        let forbidden = #"(?i)\b(insert|update|delete|drop|alter|create|truncate|copy|grant|revoke|replace|merge|attach|detach|load|call|execute|do|set|lock|vacuum|into|for\s+update|for\s+share)\b"#
        return withoutTrailingSemicolon.range(of: forbidden, options: .regularExpression) == nil
    }

    private func sftpDecision(
        _ descriptor: SecretOperationDescriptor
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        switch descriptor.effectiveFileOperation {
        case .list, .read:
            return (.silent, .none, ["SFTP 操作被本地解析为只读"], "sftp.read.silent")
        case .download:
            guard let target = descriptor.fileTarget,
                  isWithinSafeDownloadDirectory(target)
            else {
                return (
                    .approvalRequired,
                    .freshApprovalRequired,
                    ["SFTP 下载目标\(descriptor.fileTarget.map { " \($0)" } ?? "")不在默认安全目录；设备所有者确认本次路径后执行"],
                    "sftp.download.fresh-approval"
                )
            }
            guard !FileManager.default.fileExists(atPath: URL(fileURLWithPath: target).standardizedFileURL.path) else {
                return (
                    .approvalRequired,
                    .freshApprovalRequired,
                    ["SFTP 下载目标已存在，覆盖需要设备所有者确认"],
                    "sftp.download.overwrite.fresh-approval"
                )
            }
            return (
                .approvalRequired,
                .reusableApproval,
                ["SFTP 下载写入专用安全目录且不覆盖现有文件，首次需要本机审批"],
                "sftp.download.reusable-approval"
            )
        case .upload:
            return (
                .approvalRequired,
                .reusableApproval,
                ["SFTP 上传为新文件写入，首次需要本机审批，之后可在执行窗口内复用"],
                "sftp.upload.reusable-approval"
            )
        case .write, .overwrite, .delete, .move:
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["SFTP/SCP 操作会覆盖、删除或移动远端数据，每次都需要设备所有者重新认证"],
                "sftp.destructive.fresh-approval"
            )
        case .none:
            return (
                .approvalRequired,
                .reusableApproval,
                ["SFTP 传输为普通操作，首次需要本机审批，之后可在执行窗口内复用"],
                "sftp.transfer.reusable-approval"
            )
        }
    }

    private func actionNeedsSecret(_ action: SecretOperationAction) -> Bool {
        switch action {
        case .vaultStatus, .usagePolicy, .inspectReference, .checkReferenceExists,
             .deleteSecret, .changeSecretPolicy, .changeDestinationBinding,
             .changeAllowlist, .changeAuthorizationRules, .changeKeychain,
             .migrateMasterKey, .importRecoveryKey, .exportRecoveryKey,
             .restoreVault, .clearVault, .batchDelete, .resetVault:
            return false
        default:
            return true
        }
    }

    private func isAllowedSecretPolicy(_ policy: SecretPolicy, action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand, .httpRequest, .apiRequest, .databaseQuery, .sftpTransfer,
             .browserLogin, .localAppFill, .trustedProcess:
            return policy == .credential || policy == .externalSend
        default:
            return true
        }
    }

    private func isAllowedProtocol(
        _ protocolType: SecretOperationProtocol,
        for descriptor: SecretOperationDescriptor,
        allowedProtocols: [String]
    ) -> Bool {
        if allowedProtocols.contains(where: { $0.lowercased() == protocolType.rawValue.lowercased() }) {
            return true
        }
        // `http-loopback` is a profile transport-policy marker, not a new
        // wire protocol. It still satisfies the ordinary HTTP binding check.
        if protocolType == .http,
           allowedProtocols.contains(where: { $0.lowercased() == "http-loopback" }) {
            return true
        }
        guard descriptor.actionType == .browserLogin,
              let url = descriptor.url,
              let scheme = URL(string: url)?.scheme?.lowercased() else {
            return false
        }
        return allowedProtocols.contains(where: { $0.lowercased() == scheme })
    }

    private func isWithinSafeDownloadDirectory(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let root = configuration.safeDownloadDirectory.standardizedFileURL
        let parent = url.deletingLastPathComponent()
        let resolvedRoot = root.resolvingSymlinksInPath()
        let resolvedParent = parent.resolvingSymlinksInPath()
        return resolvedParent.path.hasPrefix(resolvedRoot.path + "/")
            || resolvedParent.path == resolvedRoot.path
    }

    private func isPublicDestination(_ destination: String) -> Bool {
        let host: String = {
            let candidate = destination.contains("://") ? destination : "//\(destination)"
            if let parsedHost = URLComponents(string: candidate)?.host {
                return parsedHost
                    .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                    .trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    .lowercased()
            }
            return destination.split(separator: ":", maxSplits: 1).first.map(String.init)?.lowercased() ?? destination.lowercased()
        }()
        if host.hasPrefix("/") || host.hasPrefix("file/") {
            return false
        }
        if host == "localhost" || host.hasSuffix(".localhost")
            || host.hasSuffix(".local") || host.hasSuffix(".lan")
            || host.hasSuffix(".internal") || host.hasSuffix(".home.arpa") {
            return false
        }
        if host.contains(":") {
            let compact = host.replacingOccurrences(of: " ", with: "")
            let isPrivateIPv6 = compact == "::"
                || compact == "::1"
                || compact.hasPrefix("fc")
                || compact.hasPrefix("fd")
                || (compact.hasPrefix("fe8") || compact.hasPrefix("fe9")
                    || compact.hasPrefix("fea") || compact.hasPrefix("feb"))
            return !isPrivateIPv6
        }
        let looksLikeNumericIPv4 = host.unicodeScalars.allSatisfy { $0.value == 0x2E || (0x30...0x39).contains($0.value) }
        if looksLikeNumericIPv4 {
            let components = host.split(separator: ".", omittingEmptySubsequences: false)
            guard components.count == 4,
                  components.allSatisfy({ component in
                      !component.isEmpty
                          && (component.count == 1 || component.first != "0")
                          && component.allSatisfy { $0.isNumber }
                  }) else {
                return true
            }
            let parts = components.compactMap { Int($0) }
            guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else {
                return true
            }
            let first = parts[0]
            let second = parts[1]
            if first == 0 || first == 10 || first == 127 || (first == 100 && (64...127).contains(second))
                || (first == 192 && second == 168) || (first == 169 && second == 254)
                || (first == 172 && (16...31).contains(second)) {
                return false
            }
            return true
        }
        // A hostname with no dot is not proof of a private/local target. Keep
        // the explicit localhost/.local allowlist above, but classify every
        // other unknown or single-label name as public/untrusted for the
        // warning text only.
        return true
    }

    private func explicitPort(in destination: String) -> Int? {
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: trimmed), url.scheme != nil {
            return url.port
        }
        return URL(string: "//\(trimmed)")?.port
    }

    private func hasCredentialQueryParameter(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return true
        }
        return components.queryItems?.contains { item in
            item.name.range(of: #"(?i)password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie"#, options: .regularExpression) != nil
        } == true
    }

    private func referencesMatch(_ lhs: [SecretReference], _ rhs: [SecretReference]) -> Bool {
        lhs.count == rhs.count
            && Set(lhs).count == lhs.count
            && Set(rhs).count == rhs.count
            && Set(lhs) == Set(rhs)
    }

    private func decision(
        _ risk: OperationRisk,
        _ reasons: [String],
        _ ruleID: String,
        _ destination: String?,
        authorizationRequirement: AuthorizationRequirement? = nil,
        technicalFailure: Bool = false
    ) -> PolicyDecision {
        PolicyDecision(
            risk: risk,
            reasons: reasons,
            normalizedDestination: destination,
            requiredApproval: (authorizationRequirement ?? risk.authorizationRequirement).requiresApproval,
            policyRuleID: ruleID,
            authorizationRequirement: authorizationRequirement,
            requiresFreshApprovalOnFirstUse: false,
            technicalFailure: technicalFailure
        )
    }

    private static func sanitizeReason(_ reason: String) -> String {
        String(reason.replacingOccurrences(of: "\n", with: " ").prefix(240))
    }
}
