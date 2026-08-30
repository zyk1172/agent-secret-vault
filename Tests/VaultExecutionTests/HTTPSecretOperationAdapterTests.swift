import Foundation
import Testing
import VaultCore
@testable import VaultExecution

private let httpTestReference = "secret://0123456789ABCDEFGHJKMNPQRS"
private let httpTestHost = "svlt.local"

@Test func typedHTTPAdapterReusesTransportAndNeverPreviewsAuthenticatedBody() async throws {
    let reference = try SecretReference(httpTestReference)
    let manager = HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    let adapter = HTTPSecretOperationAdapter(sessionManager: manager)
    let payload = SecretOperationPayload.http(
        HTTPOperation(
            method: .get,
            auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
            responsePolicy: HTTPResponsePolicy(kind: .sanitizedPreview)
        )
    )

    func makeDescriptor(sessionID: String? = nil) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: httpTestHost,
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://\(httpTestHost)/ok?limit=10",
            sessionID: sessionID,
            payload: payload,
            requestedEffects: ["read-only"]
        )
    }

    let context = SecretOperationExecutionContext(principal: "test-principal", securityGeneration: 1)
    let first = try await adapter.execute(
        makeDescriptor(),
        metadata: [httpMetadata(reference)],
        context: context,
        resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
    )
    let second = try await adapter.execute(
        makeDescriptor(sessionID: first.sessionID),
        metadata: [httpMetadata(reference)],
        context: context,
        resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
    )

    #expect(first.status == "COMPLETED")
    #expect(second.status == "COMPLETED")
    #expect(first.sessionID?.hasPrefix("http_session_") == true)
    #expect(second.sessionID == first.sessionID)
    #expect(first.bodyPreview == nil)
    #expect(second.bodyPreview == nil)
    #expect(await manager.activeSessionCount(for: "test-principal") == 1)
}

@Test func typedHTTPAdapterRejectsRedirectsBeforeReturningAResponse() async throws {
    let reference = try SecretReference(httpTestReference)
    let manager = HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    let adapter = HTTPSecretOperationAdapter(sessionManager: manager)
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/redirect",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference)
            )
        ),
        requestedEffects: ["read-only"]
    )
    let context = SecretOperationExecutionContext(principal: "redirect-principal", securityGeneration: 1)

    await #expect(throws: SecretOperationExecutionError.redirectRequiresReview) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [httpMetadata(reference)],
            context: context,
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func typedHTTPAdapterRejectsInsecureSecretTransportWithoutProfileOptIn() async throws {
    let reference = try SecretReference(httpTestReference)
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/ok",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference)
            )
        )
    )

    await #expect(throws: SecretOperationExecutionError.insecureTransportDenied) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [],
            context: SecretOperationExecutionContext(principal: "insecure-http", securityGeneration: 1),
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func typedHTTPAdapterRejectsInsecureSecretTransportOnAnUnprofiledPort() async throws {
    let reference = try SecretReference(httpTestReference)
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/ok",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference)
            )
        )
    )

    await #expect(throws: SecretOperationExecutionError.insecureTransportDenied) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [SecretPolicyMetadata(
                reference: reference,
                policy: .credential,
                label: "HTTP test credential",
                allowedDestinations: ["\(httpTestHost):8080"],
                allowedProtocols: ["http"]
            )],
            context: SecretOperationExecutionContext(principal: "insecure-port", securityGeneration: 1),
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func typedHTTPAdapterEnforcesStreamingResponseLimit() async throws {
    let reference = try SecretReference(httpTestReference)
    let manager = HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: manager,
        outputLimitBytes: 8
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/large",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                responsePolicy: HTTPResponsePolicy(kind: .sanitizedPreview, maxBytes: 8)
            )
        ),
        requestedEffects: ["read-only"]
    )
    let context = SecretOperationExecutionContext(principal: "limit-principal", securityGeneration: 1)

    await #expect(throws: SecretOperationExecutionError.outputLimitExceeded) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [httpMetadata(reference)],
            context: context,
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func typedHTTPAdapterUsesAnExplicitCredentialHeaderAllowlist() throws {
    let reference = try SecretReference(httpTestReference)
    let adapter = HTTPSecretOperationAdapter()

    func descriptor(headerName: String) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: httpTestHost,
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://\(httpTestHost)/ok",
            payload: .http(
                HTTPOperation(
                    method: .get,
                    auth: HTTPAuthStrategy(
                        kind: .apiKeyHeader,
                        valueReference: reference,
                        headerName: headerName
                    )
                )
            )
        )
    }

    #expect(adapter.preflight(descriptor(headerName: "X-API-Key")) == .supported)
    #expect(adapter.preflight(descriptor(headerName: "Authorization")) == .invalidParameters)
    #expect(adapter.preflight(descriptor(headerName: "X-Internal-Secret")) == .invalidParameters)
}

@Test func typedHTTPAdapterRejectsUnimplementedResponseSelectorsAndHonorsUTF8ByteLimit() async throws {
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    )
    let unsupportedResponsePolicyDescriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/ok",
        payload: .http(
            HTTPOperation(
                responsePolicy: HTTPResponsePolicy(
                    kind: .structuredFields,
                    fields: ["ok"],
                    selector: "data.token"
                )
            )
        )
    )
    #expect(adapter.preflight(unsupportedResponsePolicyDescriptor) == .unavailable)

    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/unicode",
        payload: .http(
            HTTPOperation(
                responsePolicy: HTTPResponsePolicy(kind: .sanitizedPreview, maxBytes: 3)
            )
        )
    )
    let output = try await adapter.execute(
        descriptor,
        metadata: [],
        context: SecretOperationExecutionContext(principal: "utf8-principal", securityGeneration: 1),
        resolve: { _ in Data() }
    )
    #expect(output.bodyPreview == "中")
    #expect(Data((output.bodyPreview ?? "").utf8).count <= 3)
}

@Test func typedHTTPAdapterReturnsOnlyProfileApprovedJSONProjectionForAuthenticatedResponse() async throws {
    let reference = try SecretReference(httpTestReference)
    let profile = HTTPResponseProjectionProfile(
        id: "status-profile",
        origin: "http://\(httpTestHost)",
        allowedMethods: [.get],
        path: "/projected",
        allowedJSONPointers: ["/status", "/data"]
    )
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration),
        responseProjectionProfiles: [profile]
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/projected",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                responsePolicy: HTTPResponsePolicy(
                    kind: .projectedJSON,
                    fields: ["/status"],
                    profileID: profile.id
                )
            )
        )
    )

    let output = try await adapter.execute(
        descriptor,
        metadata: [httpMetadata(reference)],
        context: SecretOperationExecutionContext(principal: "projection", securityGeneration: 1),
        resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
    )

    #expect(output.bodyPreview == "{\"status\":\"ok\"}")
    #expect(!(output.bodyPreview ?? "").contains("access_token"))
}

@Test func typedHTTPProjectionProfileBindsTheExactMethodAndPath() throws {
    let reference = try SecretReference(httpTestReference)
    let profile = HTTPResponseProjectionProfile(
        id: "exact-profile",
        origin: "http://\(httpTestHost)",
        allowedMethods: [.get],
        path: "/projected",
        allowedJSONPointers: ["/status"]
    )
    let adapter = HTTPSecretOperationAdapter(responseProjectionProfiles: [profile])

    func descriptor(method: HTTPMethod, path: String) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: httpTestHost,
            port: 80,
            protocolType: .http,
            httpMethod: method.rawValue,
            url: "http://\(httpTestHost)\(path)",
            payload: .http(
                HTTPOperation(
                    method: method,
                    auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                    responsePolicy: HTTPResponsePolicy(
                        kind: .projectedJSON,
                        fields: ["/status"],
                        profileID: profile.id
                    )
                )
            )
        )
    }

    #expect(adapter.preflight(descriptor(method: .get, path: "/projected")) == .supported)
    #expect(adapter.preflight(descriptor(method: .get, path: "/other")) == .invalidParameters)
    #expect(adapter.preflight(descriptor(method: .post, path: "/projected")) == .invalidParameters)
}

@Test func typedHTTPProjectionProfileComparesTheEncodedWirePath() throws {
    let reference = try SecretReference(httpTestReference)
    let profile = HTTPResponseProjectionProfile(
        id: "encoded-path-profile",
        origin: "http://\(httpTestHost)",
        allowedMethods: [.get],
        path: "/a/b",
        allowedJSONPointers: ["/status"]
    )
    let adapter = HTTPSecretOperationAdapter(responseProjectionProfiles: [profile])

    func descriptor(path: String) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: httpTestHost,
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://\(httpTestHost)\(path)",
            payload: .http(
                HTTPOperation(
                    method: .get,
                    auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                    responsePolicy: HTTPResponsePolicy(
                        kind: .projectedJSON,
                        fields: ["/status"],
                        profileID: profile.id
                    )
                )
            )
        )
    }

    #expect(adapter.preflight(descriptor(path: "/a/b")) == .supported)
    // `/a%2Fb` decodes to `/a/b`, but the wire request keeps the encoded
    // path, so the endpoint profile must not match it.
    #expect(adapter.preflight(descriptor(path: "/a%2Fb")) == .invalidParameters)
    // Any percent-encoding variation fails the exact path comparison.
    #expect(adapter.preflight(descriptor(path: "/a%62")) == .invalidParameters)
}

@Test func typedHTTPAdapterQuarantinesSensitiveFieldsInsideProjectedJSON() async throws {
    let reference = try SecretReference(httpTestReference)
    let profile = HTTPResponseProjectionProfile(
        id: "data-profile",
        origin: "http://\(httpTestHost)",
        allowedMethods: [.get],
        path: "/sensitive",
        allowedJSONPointers: ["/data"]
    )
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration),
        responseProjectionProfiles: [profile]
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/sensitive",
        payload: .http(
            HTTPOperation(
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                responsePolicy: HTTPResponsePolicy(
                    kind: .projectedJSON,
                    fields: ["/data"],
                    profileID: profile.id
                )
            )
        )
    )

    await #expect(throws: SecretOperationExecutionError.outputQuarantined) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [httpMetadata(reference)],
            context: SecretOperationExecutionContext(principal: "projection-sensitive", securityGeneration: 1),
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func typedHTTPAdapterRejectsSensitiveProjectedFieldEvenWhenProfileListsIt() async throws {
    let reference = try SecretReference(httpTestReference)
    let profile = HTTPResponseProjectionProfile(
        id: "unsafe-profile",
        origin: "http://(httpTestHost)",
        allowedMethods: [.get],
        path: "/projected",
        allowedJSONPointers: ["/access_token"]
    )
    let adapter = HTTPSecretOperationAdapter(
        sessionManager: HTTPSessionManager(configurationProvider: testURLSessionConfiguration),
        responseProjectionProfiles: [profile]
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://(httpTestHost)/projected",
        payload: .http(
            HTTPOperation(
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                responsePolicy: HTTPResponsePolicy(
                    kind: .projectedJSON,
                    fields: ["/access_token"],
                    profileID: profile.id
                )
            )
        )
    )

    #expect(adapter.preflight(descriptor) == .invalidParameters)
    await #expect(throws: SecretOperationExecutionError.invalidParameter) {
        _ = try await adapter.execute(
            descriptor,
            metadata: [httpMetadata(reference)],
            context: SecretOperationExecutionContext(principal: "projection-unsafe", securityGeneration: 1),
            resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
        )
    }
}

@Test func concurrentRedirectsKeepTheirOwnRejectionState() async throws {
    let reference = try SecretReference(httpTestReference)
    let manager = HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    let adapter = HTTPSecretOperationAdapter(sessionManager: manager)
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: httpTestHost,
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://\(httpTestHost)/redirect",
        payload: .http(
            HTTPOperation(
                method: .get,
                auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference)
            )
        )
    )
    let context = SecretOperationExecutionContext(principal: "redirect-concurrent", securityGeneration: 1)

    var outcomes: [Bool] = []
    await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<2 {
            group.addTask {
                do {
                    _ = try await adapter.execute(
                        descriptor,
                        metadata: [httpMetadata(reference)],
                        context: context,
                        resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
                    )
                    return false
                } catch let error as SecretOperationExecutionError {
                    return error == .redirectRequiresReview
                } catch {
                    return false
                }
            }
        }
        for await outcome in group {
            outcomes.append(outcome)
        }
    }
    #expect(outcomes.count == 2)
    #expect(outcomes.allSatisfy { $0 })
}

private func testURLSessionConfiguration() -> URLSessionConfiguration {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [DeterministicHTTPURLProtocol.self]
    return configuration
}

private func httpMetadata(_ reference: SecretReference) -> SecretPolicyMetadata {
    SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "HTTP test credential",
        allowedDestinations: ["\(httpTestHost):80"],
        allowedProtocols: ["http"]
    )
}

private final class DeterministicHTTPURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == httpTestHost
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        let isRedirect = url.path == "/redirect"
        let isLarge = url.path == "/large"
        let isUnicode = url.path == "/unicode"
        let statusCode = isRedirect ? 302 : 200
        let headers = isRedirect
            ? ["Location": "http://\(httpTestHost)/ok"]
            : ["Content-Type": "application/json"]
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        ) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !isRedirect {
            let data = isLarge
                ? Data("0123456789abcdef".utf8)
                : isUnicode
                    ? Data("中a".utf8)
                : url.path == "/projected"
                    ? Data("{\"status\":\"ok\",\"access_token\":\"derived-secret\"}".utf8)
                : url.path == "/sensitive"
                    ? Data("{\"data\":{\"token\":\"derived-secret\"}}".utf8)
                : Data("{\"ok\":true}".utf8)
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
