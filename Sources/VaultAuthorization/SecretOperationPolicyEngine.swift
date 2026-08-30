import Foundation
import VaultCore

/// The single local decision point for operations that may use a secret.
/// Callers may provide an agent assessment, but the assessment is only a
/// bounded hint.  The local result is always combined with it using max().
public struct SecretOperationPolicyEngine: Sendable {
    public struct Configuration: Sendable {
        public let maxCommandLength: Int
        public let safeDownloadDirectory: URL

        public init(
            maxCommandLength: Int = 2_000,
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
            reasons.append("Agent 声明风险为 \(agentRisk.rawValue)，只能升高不能降低本地判断")
        }

        return PolicyDecision(
            risk: effectiveRisk,
            reasons: reasons.map(Self.sanitizeReason),
            normalizedDestination: normalizedDestination,
            requiredApproval: effectiveRequirement.requiresApproval,
            policyRuleID: local.policyRuleID,
            authorizationRequirement: effectiveRequirement,
            requiresFreshApprovalOnFirstUse: local.requiresFreshApprovalOnFirstUse
                && effectiveRequirement == .reusableApproval
        )
    }

    /// The Agent's declared risk is a bounded hint, not authorization. It can
    /// raise the local decision, but it must not reshape the lease semantics
    /// the local policy already granted: an honest `approvalRequired` report
    /// must not push a locally reusable operation out of the five-minute
    /// execution window, and it must not mint reusable approval for a locally
    /// silent operation either. Only the local classifier grants
    /// reusable-lease semantics.
    private static func effectiveAuthorizationRequirement(
        local: AuthorizationRequirement,
        agentRisk: OperationRisk
    ) -> AuthorizationRequirement {
        switch agentRisk {
        case .silent:
            return local
        case .denied:
            return .denied
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
            return decision(.denied, [invalidShape.reason], invalidShape.ruleID, normalizedDestination)
        }

        let localRisk: OperationRisk
        let localRequirement: AuthorizationRequirement
        var requiresFreshApprovalOnFirstUse = false
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
            reasons = ["明文暴露、数据删除或安全设置变更必须本机审批"]
            ruleID = "sensitive-control.approval"
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
            let httpDecision = httpDecision(descriptor, metadata: metadata)
            localRisk = httpDecision.risk
            reasons = httpDecision.reasons
            ruleID = httpDecision.ruleID
            // A profile-approved insecure HTTP target is reusable only after
            // its first use establishes fresh device-owner presence.  The
            // transport opt-in may promote a silent request to reusable, but
            // it must never downgrade a method-specific fresh approval (for
            // example DELETE) or a denied operation.  The first-use marker
            // therefore only stays set when the effective local requirement
            // remained reusable: fresh operations never establish a lease.
            let baseRequirement = authorizationRequirement(for: descriptor, risk: localRisk)
            let transportRequirement: AuthorizationRequirement =
                httpDecision.requiresFreshApprovalOnFirstUse ? .reusableApproval : .none
            localRequirement = AuthorizationRequirement.max(baseRequirement, transportRequirement)
            requiresFreshApprovalOnFirstUse = httpDecision.requiresFreshApprovalOnFirstUse
                && localRequirement == .reusableApproval
        case .databaseQuery:
            let databaseDecision = databaseDecision(descriptor.effectiveDatabaseStatement)
            localRisk = databaseDecision.risk
            reasons = databaseDecision.reasons
            ruleID = databaseDecision.ruleID
            localRequirement = authorizationRequirement(for: descriptor, risk: localRisk)
        case .sftpTransfer:
            let transferDecision = sftpDecision(descriptor)
            localRisk = transferDecision.risk
            reasons = transferDecision.reasons
            ruleID = transferDecision.ruleID
            localRequirement = authorizationRequirement(for: descriptor, risk: localRisk)
        case .browserLogin, .localAppFill:
            localRisk = .silent
            reasons = ["绑定目标上的普通登录或表单填充"]
            ruleID = "bound-login.silent"
            localRequirement = .none
        case .localExecution:
            localRisk = .denied
            reasons = ["通用 shell 不得获得 Secret 明文"]
            ruleID = "generic-shell.denied"
            localRequirement = .denied
        case .trustedProcess:
            localRisk = .approvalRequired
            reasons = ["Trusted Process 只能通过预先配置的签名 profile 使用 Secret"]
            ruleID = "trusted-process.approval"
            localRequirement = .freshApprovalRequired
        }

        let binding = bindingDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination,
            baseRisk: localRisk
        )
        reasons.append(contentsOf: binding.reasons)
        let effectiveRequirement = AuthorizationRequirement.max(
            localRequirement,
            binding.risk.authorizationRequirement
        )
        return decision(
            OperationRisk.max(localRisk, binding.risk),
            reasons,
            binding.risk == .denied ? binding.ruleID : ruleID,
            normalizedDestination,
            authorizationRequirement: effectiveRequirement,
            requiresFreshApprovalOnFirstUse: requiresFreshApprovalOnFirstUse
                && effectiveRequirement == .reusableApproval
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
            if destination.contains("secret://") {
                return ("目标主机不能携带 Secret 引用", "ssh.destination.secret-reference")
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
            if rawURL.contains("secret://") {
                return ("URL 不能携带 Secret 引用", "http.url.secret-reference")
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
                  url.password == nil,
                  !rawURL.contains("secret://") else {
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

        let sensitiveFields = [
            descriptor.destination,
            descriptor.command,
            descriptor.url,
            descriptor.databaseStatement,
            descriptor.fileTarget,
            descriptor.localAppBundleID
        ].compactMap { $0 }
        if sensitiveFields.contains(where: { $0.contains("secret://") }) {
            return ("操作参数不能把 Secret 引用放入命令、URL 或目标字段", "operation.secret-reference-placement")
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

    private func bindingDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        normalizedDestination: String?,
        baseRisk: OperationRisk
    ) -> (risk: OperationRisk, reasons: [String], ruleID: String) {
        guard actionNeedsSecret(descriptor.actionType) else {
            return (.silent, [], "no-secret.required")
        }

        guard !descriptor.secretReferences.isEmpty else {
            return (.denied, ["需要 Secret 的操作没有提供 secret:// 引用"], "secret-reference.missing")
        }

        var metadataByReference: [SecretReference: SecretPolicyMetadata] = [:]
        for item in metadata {
            guard metadataByReference[item.reference] == nil else {
                return (.denied, ["Secret 元数据包含重复引用，无法安全复核"], "secret-metadata.duplicate")
            }
            metadataByReference[item.reference] = item
        }
        for reference in descriptor.secretReferences {
            guard let secret = metadataByReference[reference] else {
                return (.denied, ["Secret 元数据缺失，无法进行本地复核"], "secret-metadata.missing")
            }

            if let protocolType = descriptor.protocolType,
               !secret.allowedProtocols.isEmpty,
               !isAllowedProtocol(protocolType, for: descriptor, allowedProtocols: secret.allowedProtocols) {
                return (
                    .denied,
                    ["Secret 未绑定当前协议"],
                    "destination.protocol-not-allowed"
                )
            }

            if !isAllowedSecretPolicy(secret.policy, action: descriptor.actionType) {
                return (
                    .denied,
                    ["Secret 的本地 policy 不允许当前副作用"],
                    "secret-policy.effect-not-allowed"
                )
            }

            guard let normalizedDestination else {
                if baseRisk == .silent {
                    return (.denied, ["需要目的地绑定的操作缺少目的地"], "destination.missing")
                }
                continue
            }

            if (descriptor.actionType == .httpRequest
                || descriptor.actionType == .apiRequest
                || descriptor.actionType == .databaseQuery
                || descriptor.actionType == .sftpTransfer
                || descriptor.actionType == .browserLogin),
               isPublicDestination(normalizedDestination) {
                return (
                    .denied,
                    ["本地 HTTP/浏览器凭据操作只允许本机或内网可信目标"],
                    "destination.local-only-public-denied"
                )
            }

            let exactBinding = secret.allowedDestinations.contains {
                SecretOperationDescriptor.normalizeDestination($0) == normalizedDestination
            }
            if exactBinding {
                continue
            }

            if rejectsUnboundPublicDestination(for: descriptor.actionType),
               isPublicDestination(normalizedDestination) {
                return (
                    .denied,
                    ["Secret 目的地不在 allowlist，且目标不是本机或内网可信目标"],
                    "destination.public-unbound"
                )
            }

            return (
                .approvalRequired,
                ["Secret 目的地未精确绑定，需要本机审批"],
                "destination.unbound-approval"
            )
        }

        return (.silent, [], "destination.bound")
    }

    private func authorizationRequirement(
        for descriptor: SecretOperationDescriptor,
        risk: OperationRisk
    ) -> AuthorizationRequirement {
        guard risk != .denied else { return .denied }
        switch descriptor.actionType {
        case .exportPlaintext:
            return .reusableApproval
        case .revealPlaintext, .copyPlaintext, .deleteSecret,
             .changeSecretPolicy, .changeDestinationBinding, .changeAllowlist,
             .changeAuthorizationRules, .changeKeychain, .migrateMasterKey,
             .importRecoveryKey, .exportRecoveryKey, .restoreVault, .clearVault,
             .batchDelete, .resetVault:
            return .freshApprovalRequired
        case .httpRequest, .apiRequest:
            return (descriptor.effectiveHTTPMethod ?? "GET").uppercased() == "DELETE"
                ? .freshApprovalRequired
                : risk.authorizationRequirement
        case .databaseQuery:
            return databaseRequiresFreshApproval(descriptor.effectiveDatabaseStatement)
                ? .freshApprovalRequired
                : risk.authorizationRequirement
        case .sftpTransfer:
            switch descriptor.effectiveFileOperation {
            case .delete, .overwrite:
                return .freshApprovalRequired
            default:
                return risk.authorizationRequirement
            }
        case .trustedProcess:
            return .freshApprovalRequired
        case .sshCommand:
            return descriptor.sshCommandBatch == nil
                ? sshCommandClassifier.classify(command: descriptor.command).authorizationRequirement
                : sshCommandClassifier.classify(batch: descriptor.sshCommandBatch).authorizationRequirement
        default:
            return risk.authorizationRequirement
        }
    }

    private func databaseRequiresFreshApproval(_ query: String?) -> Bool {
        guard let query else { return true }
        return !isReadOnlyDatabaseQuery(query)
    }

    private func isReadOnlyDatabaseQuery(_ query: String) -> Bool {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return false }
        let withoutTrailingSemicolon = normalized.hasSuffix(";")
            ? String(normalized.dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
            : normalized
        guard !withoutTrailingSemicolon.contains(";") else { return false }
        guard withoutTrailingSemicolon.range(of: #"--|/\*|\*/"#, options: .regularExpression) == nil else {
            return false
        }
        guard withoutTrailingSemicolon.range(
            of: #"(?i)^\s*(select|with|show|describe|explain)\b"#,
            options: .regularExpression
        ) != nil else {
            return false
        }
        // `SELECT ... INTO` creates a table in PostgreSQL, while MySQL's
        // `INTO OUTFILE` writes a file. Treat every INTO form as a write until
        // a real dialect-aware parser/driver enforces read-only transactions.
        let forbidden = #"(?i)\b(insert|update|delete|drop|alter|create|truncate|copy|grant|revoke|replace|merge|attach|detach|load|call|execute|do|set|lock|vacuum|into|for\s+update|for\s+share)\b"#
        return withoutTrailingSemicolon.range(of: forbidden, options: .regularExpression) == nil
    }

    private func httpDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata]
    ) -> (
        risk: OperationRisk,
        reasons: [String],
        ruleID: String,
        requiresFreshApprovalOnFirstUse: Bool
    ) {
        guard let url = descriptor.url,
              let parsedURL = URL(string: url),
              parsedURL.user == nil,
              parsedURL.password == nil,
              (parsedURL.scheme?.lowercased() == "http" || parsedURL.scheme?.lowercased() == "https")
        else {
            return (.denied, ["HTTP URL 无效或包含 URL 内嵌凭据"], "http.url.invalid", false)
        }

        if hasCredentialQueryParameter(parsedURL) {
            return (.denied, ["禁止通过 URL query 传递 token 或凭据"], "http.url-credential-query.denied", false)
        }

        if parsedURL.scheme?.lowercased() == "http", !descriptor.secretReferences.isEmpty {
            let host = parsedURL.host ?? ""
            let effectivePort = parsedURL.port ?? 80
            guard let requestedOrigin = SecretOperationDescriptor.normalizeHTTPOrigin(
                url,
                defaultPort: effectivePort,
                allowURLPath: true
            )
            else {
                return (.denied, ["HTTP 目标主机无效"], "http.destination.invalid", false)
            }
            let profileAllowsInsecureHTTP = descriptor.secretReferences.allSatisfy { reference in
                guard let secret = metadata.first(where: { $0.reference == reference }),
                      secret.httpTransportSecurityPolicy.permitsInsecureHTTP(toHost: host) else {
                    return false
                }
                return secret.allowedDestinations.contains {
                    SecretOperationDescriptor.normalizeHTTPOrigin(
                        $0,
                        expectedScheme: "http",
                        defaultPort: 80,
                        requireExplicitPort: true
                    ) == requestedOrigin
                }
            }
            guard profileAllowsInsecureHTTP else {
                return (
                    .denied,
                    ["禁止将 Secret 发送到未由用户 profile 明确允许的未加密 HTTP 目标"],
                    "http.insecure-transport.denied",
                    false
                )
            }
        }

        let method = (descriptor.effectiveHTTPMethod ?? "GET").uppercased()
        if method == "GET" || method == "HEAD" {
            let isInsecure = parsedURL.scheme?.lowercased() == "http" && !descriptor.secretReferences.isEmpty
            return (
                .silent,
                isInsecure
                    ? ["HTTP GET/HEAD 是读取操作，但目标使用用户 profile 明确允许的未加密 HTTP；首次使用必须本机认证"]
                    : ["HTTP GET/HEAD 被本地解析为无副作用读取"],
                isInsecure ? "http.insecure-transport.first-use" : "http.read-only.silent",
                isInsecure
            )
        }

        let isInsecure = parsedURL.scheme?.lowercased() == "http" && !descriptor.secretReferences.isEmpty
        return (
            .approvalRequired,
            isInsecure
                ? ["HTTP 方法可能产生副作用且目标使用未加密 HTTP；首次使用必须本机认证"]
                : ["HTTP 方法可能产生副作用，需要本机审批"],
            isInsecure ? "http.insecure-transport.first-use" : "http.write.approval",
            isInsecure
        )
    }

    private func databaseDecision(_ query: String?) -> (risk: OperationRisk, reasons: [String], ruleID: String) {
        guard let query, !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return (.denied, ["数据库查询为空"], "database.query.missing")
        }
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let withoutTrailingSemicolon = trimmed.hasSuffix(";") ? String(trimmed.dropLast()) : trimmed
        if withoutTrailingSemicolon.contains(";") || withoutTrailingSemicolon.range(of: #"--|/\*|\*/"#, options: .regularExpression) != nil {
            return (.denied, ["数据库查询包含多语句或注释绕过风险"], "database.multi-statement.denied")
        }
        if isReadOnlyDatabaseQuery(withoutTrailingSemicolon) {
            return (.silent, ["数据库查询被本地解析为单条只读语句"], "database.read-only.silent")
        }
        return (.approvalRequired, ["数据库查询可能写入或改变数据库状态"], "database.write.approval")
    }

    private func sftpDecision(_ descriptor: SecretOperationDescriptor) -> (risk: OperationRisk, reasons: [String], ruleID: String) {
        switch descriptor.effectiveFileOperation {
        case .list:
            return (.silent, ["SFTP list 被本地解析为只读操作"], "sftp.list.silent")
        case .download:
            guard let target = descriptor.fileTarget,
                  isWithinSafeDownloadDirectory(target)
            else {
                return (.approvalRequired, ["SFTP 下载目标不在 SVLT 专用安全目录"], "sftp.download.approval")
            }
            guard !FileManager.default.fileExists(atPath: URL(fileURLWithPath: target).standardizedFileURL.path) else {
                return (.approvalRequired, ["SFTP 下载目标已存在，禁止静默覆盖"], "sftp.download.overwrite-approval")
            }
            return (.silent, ["SFTP 下载写入专用安全目录且不覆盖现有文件"], "sftp.download.silent")
        case .upload, .overwrite, .delete, .write, .move:
            return (.approvalRequired, ["SFTP/SCP 操作会写入、覆盖或删除数据"], "sftp.write.approval")
        case .read, .none:
            return (.silent, ["SFTP 读取操作"], "sftp.read.silent")
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
        // wire protocol. It still needs to satisfy the ordinary HTTP binding
        // check before the narrower loopback host check runs below.
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
        // other unknown or single-label name as public/untrusted.
        return true
    }

    private func rejectsUnboundPublicDestination(for action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand, .httpRequest, .apiRequest, .databaseQuery, .sftpTransfer, .browserLogin,
             .trustedProcess:
            return true
        default:
            return false
        }
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
        requiresFreshApprovalOnFirstUse: Bool = false
    ) -> PolicyDecision {
        PolicyDecision(
            risk: risk,
            reasons: reasons,
            normalizedDestination: destination,
            requiredApproval: (authorizationRequirement ?? risk.authorizationRequirement).requiresApproval,
            policyRuleID: ruleID,
            authorizationRequirement: authorizationRequirement,
            requiresFreshApprovalOnFirstUse: requiresFreshApprovalOnFirstUse
        )
    }

    private static func sanitizeReason(_ reason: String) -> String {
        String(reason.replacingOccurrences(of: "\n", with: " ").prefix(240))
    }

}
