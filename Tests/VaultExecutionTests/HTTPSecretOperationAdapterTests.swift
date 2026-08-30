import Foundation
import Testing
import VaultCore
@testable import VaultExecution

private let httpTestReference = "secret://0123456789ABCDEFGHJKMNPQRS"

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
            destination: "svlt.test",
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://svlt.test/ok",
            sessionID: sessionID,
            payload: payload,
            requestedEffects: ["read-only"]
        )
    }

    let context = SecretOperationExecutionContext(principal: "test-principal", securityGeneration: 1)
    let first = try await adapter.execute(
        makeDescriptor(),
        metadata: [],
        context: context,
        resolve: { _ in Data("ASV_HTTP_TEST_TOKEN".utf8) }
    )
    let second = try await adapter.execute(
        makeDescriptor(sessionID: first.sessionID),
        metadata: [],
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
        destination: "svlt.test",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://svlt.test/redirect",
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
            metadata: [],
            context: context,
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
        destination: "svlt.test",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://svlt.test/large",
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
            metadata: [],
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
            destination: "svlt.test",
            port: 80,
            protocolType: .http,
            httpMethod: "GET",
            url: "http://svlt.test/ok",
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
        destination: "svlt.test",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://svlt.test/ok",
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
        destination: "svlt.test",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://svlt.test/unicode",
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

@Test func concurrentRedirectsKeepTheirOwnRejectionState() async throws {
    let reference = try SecretReference(httpTestReference)
    let manager = HTTPSessionManager(configurationProvider: testURLSessionConfiguration)
    let adapter = HTTPSecretOperationAdapter(sessionManager: manager)
    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [reference],
        destination: "svlt.test",
        port: 80,
        protocolType: .http,
        httpMethod: "GET",
        url: "http://svlt.test/redirect",
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
                        metadata: [],
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

private final class DeterministicHTTPURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "svlt.test"
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
            ? ["Location": "http://svlt.test/ok"]
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
                : Data("{\"ok\":true}".utf8)
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
