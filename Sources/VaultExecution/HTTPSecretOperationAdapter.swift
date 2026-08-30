import Foundation
import VaultCore

/// HTTP is deliberately limited to a small set of typed authentication
/// strategies. There is no arbitrary header dictionary: that prevents an
/// Agent from smuggling credentials through Host, Cookie, proxy, or forwarding
/// headers and keeps the response policy reviewable.
public struct HTTPSecretOperationAdapter: SecretOperationAdapter {
    public let kind: SecretAdapterKind = .http
    public let capability: SecretOperationCapability

    private let sessionManager: HTTPSessionManager
    private let outputSanitizer: OutputSanitizer
    private let defaultTimeout: Duration
    private let outputLimitBytes: Int

    public init(
        sessionManager: HTTPSessionManager = HTTPSessionManager(),
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        defaultTimeout: Duration = .seconds(30),
        outputLimitBytes: Int = 1_048_576
    ) {
        self.sessionManager = sessionManager
        self.outputSanitizer = outputSanitizer
        self.defaultTimeout = defaultTimeout
        self.outputLimitBytes = max(1, outputLimitBytes)
        self.capability = SecretOperationCapability(
            kind: .http,
            status: .supported,
            operations: [.httpRequest, .apiRequest],
            reason: "typed HTTP Basic/Bearer/API-key requests with redirect rejection"
        )
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        do {
            _ = try makePlan(for: descriptor)
            return .supported
        } catch HTTPAdapterError.unsupportedStrategy {
            return .unavailable
        } catch {
            return .invalidParameters
        }
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        let plan = try makePlan(for: descriptor)
        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        var request = URLRequest(url: plan.url)
        request.httpMethod = plan.method.rawValue
        request.timeoutInterval = plan.timeout.timeInterval
        try applyBody(plan.body, to: &request)
        let hasSecretAuth = try await applyAuthentication(
            plan.auth,
            descriptor: descriptor,
            to: &request,
            secretBuffers: &secretBuffers,
            resolve: resolve
        )

        let scope = HTTPSessionScope(
            principal: context.principal,
            scheme: plan.url.scheme ?? "http",
            host: plan.url.host ?? "",
            port: plan.url.port ?? (plan.url.scheme?.lowercased() == "https" ? 443 : 80),
            authenticationProfile: plan.auth.auditProfile,
            secretReferenceIDs: descriptor.secretReferences.map(\.description),
            securityGeneration: context.securityGeneration
        )

        let response: HTTPTransportResponse
        do {
            response = try await sessionManager.execute(
                request: request,
                scope: scope,
                requestedSessionID: descriptor.sessionID,
                maxResponseBytes: outputLimitBytes
            )
        } catch let error as HTTPSessionManagerError {
            throw mapSessionError(error)
        } catch let error as URLError where error.code == .timedOut {
            throw SecretOperationExecutionError.timedOut
        } catch is CancellationError {
            throw SecretOperationExecutionError.timedOut
        } catch {
            throw SecretOperationExecutionError.processFailed
        }

        guard response.data.count <= outputLimitBytes else {
            throw SecretOperationExecutionError.outputLimitExceeded
        }

        let sanitizedBody: String
        switch outputSanitizer.sanitize(
            ProcessResult(exitCode: 0, stdout: response.data, stderr: Data()),
            secrets: secretBuffers
        ) {
        case .quarantined:
            throw SecretOperationExecutionError.outputQuarantined
        case let .sanitized(result):
            guard let body = String(data: result.stdout, encoding: .utf8) else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            sanitizedBody = body
        }

        let bodyPreview = try responsePreview(
            plan.responsePolicy,
            body: sanitizedBody,
            hasSecretAuth: hasSecretAuth
        )
        return SecretOperationOutput(
            status: response.statusCode >= 400 ? "HTTP_ERROR" : "COMPLETED",
            httpStatus: response.statusCode,
            contentType: response.contentType,
            bodyPreview: bodyPreview,
            sessionID: response.sessionID,
            redacted: true
        )
    }

    public func invalidateSecurityState() async {
        await sessionManager.invalidateAll()
    }

    private struct RequestPlan {
        let url: URL
        let method: HTTPMethod
        let auth: HTTPAuthStrategy
        let body: HTTPBody
        let responsePolicy: HTTPResponsePolicy
        let timeout: Duration
    }

    private enum HTTPAdapterError: Error {
        case unsupportedStrategy
        case invalidParameter
    }

    private func makePlan(for descriptor: SecretOperationDescriptor) throws -> RequestPlan {
        guard descriptor.actionType == .httpRequest || descriptor.actionType == .apiRequest,
              let rawURL = descriptor.url,
              let url = URL(string: rawURL),
              url.user == nil,
              url.password == nil,
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host?.isEmpty == false,
              !rawURL.contains("secret://"),
              !hasCredentialQueryParameter(url)
        else {
            throw HTTPAdapterError.invalidParameter
        }

        let method: HTTPMethod
        let auth: HTTPAuthStrategy
        let body: HTTPBody
        let responsePolicy: HTTPResponsePolicy
        let timeoutMilliseconds: Int?

        if let payload = descriptor.payload {
            guard case let .http(operation) = payload else {
                throw HTTPAdapterError.invalidParameter
            }
            method = operation.method
            auth = operation.auth
            body = operation.body
            responsePolicy = operation.responsePolicy
            timeoutMilliseconds = operation.timeoutMs
            guard referencesMatch(operation.auth.referencedSecretReferences, descriptor.secretReferences) else {
                throw HTTPAdapterError.invalidParameter
            }
        } else {
            method = try parseMethod(descriptor.httpMethod)
            body = try legacyBody(from: descriptor)
            responsePolicy = descriptor.parameters["includeBodyPreview"] == "true"
                ? HTTPResponsePolicy(kind: .sanitizedPreview)
                : .metadataOnly
            timeoutMilliseconds = descriptor.parameters["timeoutMs"].flatMap(Int.init)
            if descriptor.actionType == .httpRequest,
               let passwordReference = reference(for: "passwordRef", in: descriptor) {
                let usernameReference = reference(for: "usernameRef", in: descriptor)
                auth = HTTPAuthStrategy(
                    kind: .basic,
                    username: descriptor.parameters["username"],
                    usernameReference: usernameReference,
                    passwordReference: passwordReference
                )
            } else if descriptor.actionType == .apiRequest,
                      let tokenReference = reference(for: "tokenRef", in: descriptor) {
                auth = HTTPAuthStrategy(
                    kind: .bearer,
                    valueReference: tokenReference,
                    scheme: descriptor.parameters["headerScheme"] ?? "Bearer"
                )
            } else {
                auth = .none
            }
        }

        guard let timeoutMilliseconds else {
            return RequestPlan(
                url: url,
                method: method,
                auth: try validateAuth(auth, descriptor: descriptor),
                body: try validateBody(body),
                responsePolicy: try validateResponsePolicy(responsePolicy),
                timeout: defaultTimeout
            )
        }
        guard (100...30_000).contains(timeoutMilliseconds) else {
            throw HTTPAdapterError.invalidParameter
        }
        return RequestPlan(
            url: url,
            method: method,
            auth: try validateAuth(auth, descriptor: descriptor),
            body: try validateBody(body),
            responsePolicy: try validateResponsePolicy(responsePolicy),
            timeout: .milliseconds(timeoutMilliseconds)
        )
    }

    private func parseMethod(_ rawValue: String?) throws -> HTTPMethod {
        guard let rawValue, let method = HTTPMethod(rawValue: rawValue.uppercased()) else {
            throw HTTPAdapterError.invalidParameter
        }
        return method
    }

    private func legacyBody(from descriptor: SecretOperationDescriptor) throws -> HTTPBody {
        guard let body = descriptor.parameters["body"] else { return .none }
        guard body.utf8.count <= 65_536, !body.contains("secret://") else {
            throw HTTPAdapterError.invalidParameter
        }
        return .raw(body)
    }

    private func validateAuth(
        _ auth: HTTPAuthStrategy,
        descriptor: SecretOperationDescriptor
    ) throws -> HTTPAuthStrategy {
        let references = auth.referencedSecretReferences
        guard referencesMatch(references, descriptor.secretReferences) else {
            throw HTTPAdapterError.invalidParameter
        }
        switch auth.kind {
        case .none:
            guard references.isEmpty,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.valueReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil,
                  auth.cookieName == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .basic:
            guard auth.passwordReference != nil,
                  (auth.username != nil) != (auth.usernameReference != nil),
                  auth.username.map(Self.isSafeUsername) ?? true,
                  auth.valueReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil,
                  auth.cookieName == nil
            else { throw HTTPAdapterError.invalidParameter }
        case .bearer:
            guard auth.valueReference != nil,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.cookieName == nil,
                  auth.headerName == nil || auth.headerName?.caseInsensitiveCompare("Authorization") == .orderedSame,
                  auth.scheme.map(Self.isSafeAuthScheme) ?? true else {
                throw HTTPAdapterError.invalidParameter
            }
        case .apiKeyHeader, .customHeader:
            guard let headerName = auth.headerName,
                  Self.isAllowedSecretHeaderName(headerName),
                  Self.isSafeHeaderName(headerName),
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.cookieName == nil,
                  auth.scheme.map(Self.isSafeAuthScheme) ?? true,
                  auth.valueReference != nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .cookie:
            guard let cookieName = auth.cookieName,
                  Self.isSafeCookieName(cookieName),
                  auth.valueReference != nil,
                  auth.username == nil,
                  auth.usernameReference == nil,
                  auth.passwordReference == nil,
                  auth.headerName == nil,
                  auth.scheme == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .oauth2ClientCredentials, .oauth2RefreshToken, .clientCertificate, .hmacSigning:
            throw HTTPAdapterError.unsupportedStrategy
        }
        if let headerName = auth.headerName,
           !Self.isSafeHeaderName(headerName, allowingAuthorization: auth.kind == .bearer) {
            throw HTTPAdapterError.invalidParameter
        }
        if let scheme = auth.scheme, !Self.isSafeAuthScheme(scheme) {
            throw HTTPAdapterError.invalidParameter
        }
        return auth
    }

    private func validateBody(_ body: HTTPBody) throws -> HTTPBody {
        switch body.kind {
        case .none:
            guard body.content == nil, body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .raw:
            guard let content = body.content,
                  content.utf8.count <= 65_536,
                  !content.contains("secret://"),
                  body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .json:
            guard let content = body.content,
                  content.utf8.count <= 65_536,
                  !content.contains("secret://"),
                  (try? JSONSerialization.jsonObject(with: Data(content.utf8))) != nil,
                  body.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        case .form:
            guard body.content == nil,
                  body.fields.count <= 128,
                  body.fields.allSatisfy({ key, value in
                      key.utf8.count <= 256 && value.utf8.count <= 4_096
                          && !key.contains("secret://") && !value.contains("secret://")
                  }) else { throw HTTPAdapterError.invalidParameter }
        }
        return body
    }

    private func validateResponsePolicy(_ policy: HTTPResponsePolicy) throws -> HTTPResponsePolicy {
        guard (0...outputLimitBytes).contains(policy.maxBytes),
              policy.fields.count <= 32,
              policy.fields.allSatisfy({ field in
                  !field.isEmpty && field.utf8.count <= 128 && Self.isSafeJSONField(field)
              }) else {
            throw HTTPAdapterError.invalidParameter
        }
        if policy.kind == .captureCredential {
            throw HTTPAdapterError.unsupportedStrategy
        }
        if policy.selector != nil {
            // JSON selectors and header capture are not implemented. Reject
            // them instead of silently returning a different response shape.
            throw HTTPAdapterError.unsupportedStrategy
        }
        switch policy.kind {
        case .metadataOnly:
            guard policy.fields.isEmpty, policy.source == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .sanitizedPreview:
            guard policy.maxBytes > 0, policy.fields.isEmpty, policy.source == nil else {
                throw HTTPAdapterError.invalidParameter
            }
        case .structuredFields:
            guard policy.maxBytes > 0,
                  !policy.fields.isEmpty,
                  policy.source == nil || policy.source == .json else {
                throw HTTPAdapterError.invalidParameter
            }
        case .captureCredential:
            throw HTTPAdapterError.unsupportedStrategy
        }
        if policy.source == .header {
            throw HTTPAdapterError.unsupportedStrategy
        }
        if policy.kind == .structuredFields {
            guard !policy.fields.isEmpty else { throw HTTPAdapterError.invalidParameter }
        }
        return policy
    }

    private func applyBody(_ body: HTTPBody, to request: inout URLRequest) throws {
        switch body.kind {
        case .none:
            return
        case .raw:
            request.httpBody = Data((body.content ?? "").utf8)
        case .json:
            let data = Data((body.content ?? "").utf8)
            guard (try? JSONSerialization.jsonObject(with: data)) != nil else {
                throw SecretOperationExecutionError.invalidParameter
            }
            request.httpBody = data
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        case .form:
            var components = URLComponents()
            components.queryItems = body.fields
                .sorted { $0.key < $1.key }
                .map { URLQueryItem(name: $0.key, value: $0.value) }
            guard let encoded = components.percentEncodedQuery else {
                throw SecretOperationExecutionError.invalidParameter
            }
            request.httpBody = Data(encoded.utf8)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        }
    }

    private func applyAuthentication(
        _ auth: HTTPAuthStrategy,
        descriptor: SecretOperationDescriptor,
        to request: inout URLRequest,
        secretBuffers: inout [Data],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> Bool {
        switch auth.kind {
        case .none:
            return false
        case .basic:
            guard let passwordReference = auth.passwordReference else {
                throw SecretOperationExecutionError.missingSecretReference
            }
            let passwordData = try await resolve(passwordReference)
            guard let password = String(data: passwordData, encoding: .utf8),
                  !password.isEmpty,
                  Self.isSafeHeaderValue(password) else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            secretBuffers.append(passwordData)
            let username: String
            if let usernameReference = auth.usernameReference {
                let usernameData = try await resolve(usernameReference)
                secretBuffers.append(usernameData)
                guard let resolved = String(data: usernameData, encoding: .utf8),
                      Self.isSafeUsername(resolved) else {
                    throw SecretOperationExecutionError.invalidSecretUTF8
                }
                username = resolved
            } else if let plainUsername = auth.username, !plainUsername.isEmpty {
                username = plainUsername
            } else {
                throw SecretOperationExecutionError.invalidParameter
            }
            let credentialsData = Data("\(username):\(password)".utf8)
            let headerData = Data("Basic \(credentialsData.base64EncodedString())".utf8)
            secretBuffers.append(credentialsData)
            secretBuffers.append(headerData)
            request.setValue(String(data: headerData, encoding: .utf8), forHTTPHeaderField: "Authorization")
            return true
        case .bearer, .apiKeyHeader, .customHeader, .cookie:
            guard let reference = auth.valueReference else {
                throw SecretOperationExecutionError.missingSecretReference
            }
            let valueData = try await resolve(reference)
            secretBuffers.append(valueData)
            guard let value = String(data: valueData, encoding: .utf8),
                  !value.isEmpty,
                  Self.isSafeHeaderValue(value),
                  auth.kind != .cookie || Self.isSafeCookieValue(value) else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }
            let headerName: String
            let headerValue: String
            switch auth.kind {
            case .bearer:
                headerName = auth.headerName ?? "Authorization"
                headerValue = auth.scheme.map { "\($0) \(value)" } ?? value
            case .apiKeyHeader, .customHeader:
                headerName = auth.headerName!
                headerValue = auth.scheme.map { "\($0) \(value)" } ?? value
            case .cookie:
                headerName = "Cookie"
                headerValue = "\(auth.cookieName!)=\(value)"
            default:
                throw SecretOperationExecutionError.invalidParameter
            }
            let headerData = Data(headerValue.utf8)
            secretBuffers.append(headerData)
            request.setValue(headerValue, forHTTPHeaderField: headerName)
            return true
        case .oauth2ClientCredentials, .oauth2RefreshToken, .clientCertificate, .hmacSigning:
            throw SecretOperationExecutionError.unavailable
        }
    }

    private func responsePreview(
        _ policy: HTTPResponsePolicy,
        body: String,
        hasSecretAuth: Bool
    ) throws -> String? {
        // A credential-bearing response can contain cookies, access tokens, or
        // refresh tokens that are not among the request secrets. Metadata-only
        // is therefore mandatory until a typed capture store exists.
        guard !hasSecretAuth else { return nil }
        switch policy.kind {
        case .metadataOnly:
            return nil
        case .sanitizedPreview:
            return utf8Prefix(body, maxBytes: policy.maxBytes)
        case .structuredFields:
            guard let data = body.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            let selected = policy.fields.reduce(into: [String: Any]()) { result, field in
                if let value = object[field] { result[field] = value }
            }
            let selectedData = try JSONSerialization.data(withJSONObject: selected, options: [.sortedKeys])
            guard selectedData.count <= policy.maxBytes,
                  let result = String(data: selectedData, encoding: .utf8) else {
                throw SecretOperationExecutionError.outputQuarantined
            }
            return result
        case .captureCredential:
            throw SecretOperationExecutionError.unavailable
        }
    }

    private func reference(for parameter: String, in descriptor: SecretOperationDescriptor) -> SecretReference? {
        guard let rawReference = descriptor.parameters[parameter] else { return nil }
        return descriptor.secretReferences.first { $0.description == rawReference }
    }

    private func referencesMatch(_ lhs: [SecretReference], _ rhs: [SecretReference]) -> Bool {
        lhs.count == rhs.count
            && Set(lhs).count == lhs.count
            && Set(rhs).count == rhs.count
            && Set(lhs) == Set(rhs)
    }

    private func utf8Prefix(_ value: String, maxBytes: Int) -> String {
        guard maxBytes > 0 else { return "" }
        let data = Data(value.utf8)
        guard data.count > maxBytes else { return value }
        var length = maxBytes
        while length > 0 {
            if let prefix = String(data: data.prefix(length), encoding: .utf8) {
                return prefix
            }
            length -= 1
        }
        return ""
    }

    private func mapSessionError(_ error: HTTPSessionManagerError) -> SecretOperationExecutionError {
        switch error {
        case .sessionNotFound: return .sessionNotFound
        case .sessionExpired: return .sessionExpired
        case .scopeMismatch: return .sessionScopeMismatch
        case .sessionLimitReached: return .sessionLimitReached
        case .redirectRequiresReview: return .redirectRequiresReview
        case .responseTooLarge: return .outputLimitExceeded
        }
    }

    private func hasCredentialQueryParameter(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return true }
        return components.queryItems?.contains { item in
            item.name.range(of: #"(?i)password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie"#, options: .regularExpression) != nil
        } == true
    }

    private static func isSafeHeaderName(
        _ name: String,
        allowingAuthorization: Bool = false
    ) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 128 else { return false }
        let forbidden = [
            "host", "content-length", "connection", "transfer-encoding",
            "authorization", "cookie", "set-cookie", "proxy-authorization",
            "proxy-authenticate", "forwarded", "via", "keep-alive", "te",
            "trailer", "upgrade", "x-forwarded-for",
            "x-forwarded-host", "x-forwarded-proto"
        ]
        let normalized = name.lowercased()
        if normalized == "authorization" {
            guard allowingAuthorization else { return false }
        } else if forbidden.contains(normalized)
                    || normalized.hasPrefix("proxy-")
                    || normalized.hasPrefix("x-forwarded-") {
            return false
        }
        return name.utf8.allSatisfy { byte in
            (byte >= 0x21 && byte <= 0x39 && byte != 0x22 && byte != 0x28 && byte != 0x29
                && byte != 0x2C && byte != 0x2F && byte != 0x3A && byte != 0x3B && byte != 0x3C
                && byte != 0x3D && byte != 0x3E && byte != 0x3F && byte != 0x40)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x5E && byte <= 0x7E)
        }
    }

    private static func isSafeCookieName(_ name: String) -> Bool {
        isSafeHeaderName(name) && name.lowercased() != "cookie"
    }

    private static func isSafeCookieValue(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            byte >= 0x21 && byte <= 0x7E && byte != 0x2C && byte != 0x3B
        }
    }

    private static func isAllowedSecretHeaderName(_ name: String) -> Bool {
        [
            "api-key", "api-token", "x-api-key", "x-api-token",
            "x-access-token", "x-auth-token", "x-client-token",
            "x-service-token", "x-subscription-key", "x-rapidapi-key",
            "x-goog-api-key"
        ].contains(name.lowercased())
    }

    private static func isSafeAuthScheme(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        return value.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39)
                || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2D || byte == 0x2E || byte == 0x5F || byte == 0x7E
        }
    }

    private static func isSafeUsername(_ value: String) -> Bool {
        value.utf8.count <= 256 && isSafeHeaderValue(value)
    }

    private static func isSafeHeaderValue(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 16_384
            && !value.unicodeScalars.contains { $0.value == 0 || $0.value == 0x0A || $0.value == 0x0D }
    }

    private static func isSafeJSONField(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F && scalar.value != 0x22
        }
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
