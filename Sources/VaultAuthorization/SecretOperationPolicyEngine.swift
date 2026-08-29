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
        let effectiveRequirement = AuthorizationRequirement.max(
            local.authorizationRequirement,
            Self.agentAuthorizationRequirement(for: agentRisk)
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
            authorizationRequirement: effectiveRequirement
        )
    }

    /// The Agent can request more scrutiny, but its coarse risk hint must not
    /// be able to create a reusable lease from a locally silent operation. A
    /// self-declared `approvalRequired` therefore maps to a fresh decision;
    /// only the local classifier grants reusable-lease semantics.
    private static func agentAuthorizationRequirement(
        for risk: OperationRisk
    ) -> AuthorizationRequirement {
        switch risk {
        case .silent:
            return .none
        case .approvalRequired:
            return .freshApprovalRequired
        case .denied:
            return .denied
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
            let httpDecision = httpDecision(descriptor)
            localRisk = httpDecision.risk
            reasons = httpDecision.reasons
            ruleID = httpDecision.ruleID
            localRequirement = authorizationRequirement(for: descriptor, risk: localRisk)
        case .databaseQuery:
            let databaseDecision = databaseDecision(descriptor.databaseStatement)
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
        }

        let binding = bindingDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination,
            baseRisk: localRisk
        )
        reasons.append(contentsOf: binding.reasons)
        return decision(
            OperationRisk.max(localRisk, binding.risk),
            reasons,
            binding.risk == .denied ? binding.ruleID : ruleID,
            normalizedDestination,
            authorizationRequirement: AuthorizationRequirement.max(
                localRequirement,
                binding.risk.authorizationRequirement
            )
        )
    }

    private func invalidOperationShape(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        if let port = descriptor.port, !(1...65_535).contains(port) {
            return ("端口不在有效范围内", "operation.port.invalid")
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
        case .httpRequest, .apiRequest, .browserLogin:
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

        let metadataByReference = Dictionary(uniqueKeysWithValues: metadata.map { ($0.reference, $0) })
        for reference in descriptor.secretReferences {
            guard let secret = metadataByReference[reference] else {
                return (.denied, ["Secret 元数据缺失，无法进行本地复核"], "secret-metadata.missing")
            }

            if let protocolType = descriptor.protocolType,
               !secret.allowedProtocols.isEmpty,
               !secret.allowedProtocols.contains(where: { $0.lowercased() == protocolType.rawValue.lowercased() }) {
                return (
                    .denied,
                    ["Secret 未绑定当前协议"],
                    "destination.protocol-not-allowed"
                )
            }

            if baseRisk == .approvalRequired,
               !isAllowedSecretPolicy(secret.policy, action: descriptor.actionType) {
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
            return (descriptor.httpMethod ?? "GET").uppercased() == "DELETE"
                ? .freshApprovalRequired
                : risk.authorizationRequirement
        case .databaseQuery:
            return databaseRequiresFreshApproval(descriptor.databaseStatement)
                ? .freshApprovalRequired
                : risk.authorizationRequirement
        case .sftpTransfer:
            switch descriptor.fileOperation {
            case .delete, .overwrite:
                return .freshApprovalRequired
            default:
                return risk.authorizationRequirement
            }
        case .sshCommand:
            return descriptor.sshCommandBatch == nil
                ? sshCommandClassifier.classify(command: descriptor.command).authorizationRequirement
                : sshCommandClassifier.classify(batch: descriptor.sshCommandBatch).authorizationRequirement
        default:
            return risk.authorizationRequirement
        }
    }

    private func databaseRequiresFreshApproval(_ query: String?) -> Bool {
        guard let query else { return false }
        let normalized = query
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: ";", with: "")
        if normalized.range(of: #"(?i)\b(drop|truncate)\b"#, options: .regularExpression) != nil {
            return true
        }
        if normalized.range(of: #"(?i)^\s*delete\b"#, options: .regularExpression) != nil,
           normalized.range(of: #"(?i)\bwhere\b"#, options: .regularExpression) == nil {
            return true
        }
        return normalized.range(of: #"(?i)\balter\b.*\bdrop\b"#, options: .regularExpression) != nil
    }

    private func httpDecision(_ descriptor: SecretOperationDescriptor) -> (risk: OperationRisk, reasons: [String], ruleID: String) {
        guard let url = descriptor.url,
              let parsedURL = URL(string: url),
              parsedURL.user == nil,
              parsedURL.password == nil,
              (parsedURL.scheme?.lowercased() == "http" || parsedURL.scheme?.lowercased() == "https")
        else {
            return (.denied, ["HTTP URL 无效或包含 URL 内嵌凭据"], "http.url.invalid")
        }

        if hasCredentialQueryParameter(parsedURL) {
            return (.denied, ["禁止通过 URL query 传递 token 或凭据"], "http.url-credential-query.denied")
        }

        let method = (descriptor.httpMethod ?? "GET").uppercased()
        if method == "GET" || method == "HEAD" {
            return (.silent, ["HTTP GET/HEAD 被本地解析为无副作用读取"], "http.read-only.silent")
        }

        return (.approvalRequired, ["HTTP 方法可能产生副作用，需要本机审批"], "http.write.approval")
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
        if withoutTrailingSemicolon.range(of: #"(?i)^(select|with|show|describe|explain)\b"#, options: .regularExpression) != nil,
           withoutTrailingSemicolon.range(of: #"(?i)\b(insert|update|delete|drop|alter|create|truncate|copy|grant|revoke|replace|merge|attach|detach|load|call|execute|do)\b"#, options: .regularExpression) == nil {
            return (.silent, ["数据库查询被本地解析为单条只读语句"], "database.read-only.silent")
        }
        return (.approvalRequired, ["数据库查询可能写入或改变数据库状态"], "database.write.approval")
    }

    private func sftpDecision(_ descriptor: SecretOperationDescriptor) -> (risk: OperationRisk, reasons: [String], ruleID: String) {
        switch descriptor.fileOperation {
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
             .browserLogin, .localAppFill:
            return policy == .credential || policy == .externalSend
        default:
            return true
        }
    }

    private func isWithinSafeDownloadDirectory(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let root = configuration.safeDownloadDirectory
        return url.deletingLastPathComponent().path.hasPrefix(root.path + "/")
            || url.deletingLastPathComponent().path == root.path
    }

    private func isPublicDestination(_ destination: String) -> Bool {
        let host = destination.split(separator: ":", maxSplits: 1).first.map(String.init) ?? destination
        if host.hasPrefix("/") || host.hasPrefix("file/") {
            return false
        }
        if host == "localhost" || host.hasSuffix(".localhost") || host == "::1"
            || host.hasSuffix(".local") || host.hasSuffix(".lan")
            || host.hasSuffix(".internal") || host.hasSuffix(".home.arpa")
            || !host.contains(".") {
            return false
        }
        let parts = host.split(separator: ".").compactMap { Int($0) }
        if parts.count == 4 {
            guard parts.allSatisfy({ (0...255).contains($0) }) else {
                return true
            }
            let first = parts[0]
            let second = parts[1]
            if first == 10 || first == 127 || (first == 192 && second == 168)
                || (first == 172 && (16...31).contains(second)) || (first == 169 && second == 254) {
                return false
            }
            return true
        }
        return true
    }

    private func rejectsUnboundPublicDestination(for action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand, .httpRequest, .apiRequest, .databaseQuery, .sftpTransfer, .browserLogin:
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

    private func decision(
        _ risk: OperationRisk,
        _ reasons: [String],
        _ ruleID: String,
        _ destination: String?,
        authorizationRequirement: AuthorizationRequirement? = nil
    ) -> PolicyDecision {
        PolicyDecision(
            risk: risk,
            reasons: reasons,
            normalizedDestination: destination,
            requiredApproval: (authorizationRequirement ?? risk.authorizationRequirement).requiresApproval,
            policyRuleID: ruleID,
            authorizationRequirement: authorizationRequirement
        )
    }

    private static func sanitizeReason(_ reason: String) -> String {
        String(reason.replacingOccurrences(of: "\n", with: " ").prefix(240))
    }

}
