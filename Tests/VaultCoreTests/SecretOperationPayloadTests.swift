import Foundation
import Testing
@testable import VaultCore

private let payloadReference = "secret://0123456789ABCDEFGHJKMNPQRS"

@Test func typedHTTPPayloadRoundTripsAndCarriesOnlyOpaqueReferences() throws {
    let passwordReference = try SecretReference(payloadReference)
    let payload = SecretOperationPayload.http(
        HTTPOperation(
            method: .post,
            auth: HTTPAuthStrategy(
                kind: .basic,
                username: "admin",
                passwordReference: passwordReference
            ),
            body: .json("{\"action\":\"status\"}"),
            responsePolicy: .metadataOnly,
            timeoutMs: 2_000
        )
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .httpRequest,
        secretReferences: [passwordReference],
        destination: "nas.local",
        port: 443,
        protocolType: .https,
        httpMethod: "POST",
        url: "https://nas.local/api/status",
        payload: payload,
        requestedEffects: ["remote-write"]
    )

    let encoded = try JSONEncoder().encode(descriptor)
    let encodedText = String(decoding: encoded, as: UTF8.self)
    #expect(encodedText.contains("\"payload\""))
    let encodedReference = passwordReference.description.replacingOccurrences(of: "/", with: "\\/")
    #expect(encodedText.contains(encodedReference))
    #expect(!encodedText.contains("ASV_CANARY_PLAINTEXT"))

    let decoded = try JSONDecoder().decode(SecretOperationDescriptor.self, from: encoded)
    #expect(decoded == descriptor)
    #expect(decoded.effectiveHTTPMethod == "POST")
}

@Test func typedPayloadReferencesMustBeDiscoverableFromThePayload() throws {
    let usernameReference = try SecretReference(payloadReference)
    let passwordReference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    let payload = SecretOperationPayload.database(
        DatabaseOperation(
            engine: .postgres,
            database: "app",
            usernameReference: usernameReference,
            passwordReference: passwordReference,
            statement: "SELECT 1",
            parameters: [
                DatabaseParameter(name: "tenant", value: .secretReference(usernameReference))
            ]
        )
    )

    let references = Set(payload.referencedSecretReferences)
    #expect(references == Set([usernameReference, passwordReference]))
}

@Test func localExecutionPayloadRoundTripsWithoutPlaintext() throws {
    let reference = try SecretReference(payloadReference)
    let payload = SecretOperationPayload.localExecution(
        LocalExecutionOperation(
            executable: "/private/tmp/svlt-check",
            arguments: ["--check-only"],
            secretReferences: [reference]
        )
    )
    let descriptor = SecretOperationDescriptor(
        actionType: .localExecution,
        secretReferences: [reference],
        destination: "/private/tmp/svlt-check",
        payload: payload,
        requestedEffects: ["user-approved-secret-release"]
    )

    let encoded = try JSONEncoder().encode(descriptor)
    let encodedText = String(decoding: encoded, as: UTF8.self)
    #expect(encodedText.contains("localExecution"))
    #expect(!encodedText.contains("ASV_CANARY_PLAINTEXT"))
    let decoded = try JSONDecoder().decode(SecretOperationDescriptor.self, from: encoded)
    #expect(decoded == descriptor)
    #expect(decoded.secretReferences == [reference])
}

@Test func typedRequestIdentityChangesWhenHTTPBodyChangesButNotWhenTransportHandleChanges() throws {
    let reference = try SecretReference(payloadReference)
    func makeDescriptor(body: String, sessionID: String? = nil) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: "nas.local",
            port: 443,
            protocolType: .https,
            httpMethod: "POST",
            url: "https://nas.local/api/action",
            sessionID: sessionID,
            payload: .http(
                HTTPOperation(
                    method: .post,
                    auth: HTTPAuthStrategy(kind: .bearer, valueReference: reference),
                    body: .json(body)
                )
            ),
            requestedEffects: ["remote-write"]
        )
    }

    let base = makeDescriptor(body: "{\"mode\":\"a\"}")
    let sameOperationWithSession = makeDescriptor(body: "{\"mode\":\"a\"}", sessionID: "http_session_opaque")
    let differentBody = makeDescriptor(body: "{\"mode\":\"b\"}")

    #expect(base.operationHash == sameOperationWithSession.operationHash)
    #expect(base.operationHash != differentBody.operationHash)
}
