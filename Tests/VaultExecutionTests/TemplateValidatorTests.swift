import Testing
import VaultAuthorization
import VaultCore
@testable import VaultExecution

@Test func rejectsUndeclaredExecutable() async {
    await expectValidationError(.undeclaredExecutable) {
        var request = validRequest()
        request.executable = "/usr/bin/env"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsExtraParameter() async {
    await expectValidationError(.undeclaredParameter("extra")) {
        var request = validRequest()
        request.values["extra"] = "unexpected"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsSecretReferenceInNonSecretField() async {
    await expectValidationError(.secretInNonSecretField("message")) {
        var request = validRequest()
        request.values["message"] = "secret://0123456789ABCDEFGHJKMNPQRS"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsDestinationHostMismatch() async {
    await expectValidationError(.destinationNotAllowed) {
        var request = validRequest()
        request.destinationHost = "evil.example.com"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsDestinationPathMismatch() async {
    await expectValidationError(.destinationNotAllowed) {
        var request = validRequest()
        request.destinationPath = "/tmp/exfiltrate"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsRiskEscalation() async {
    await expectValidationError(.riskEscalation) {
        var request = validRequest()
        request.requestedRisk = .deleteOrCredentialChange
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsShellMetacharactersInValues() async {
    await expectValidationError(.shellMetacharacters("message")) {
        var request = validRequest()
        request.values["message"] = "hello; rm -rf /"
        _ = try TemplateValidator().validate(request, against: validTemplate())
    }
}

@Test func rejectsRelativeExecutablePaths() async {
    await expectValidationError(.relativeExecutablePath) {
        let template = ExecutionTemplate(
            id: "send-message",
            executable: "curl",
            arguments: validTemplate().arguments,
            risk: .writeOrExternalSend,
            allowedHosts: ["api.example.com"],
            allowedPaths: ["/v1/send"]
        )
        _ = try TemplateValidator().validate(validRequest(), against: template)
    }
}

@Test func returnsValidatedExecutionWithoutConcatenatingCommandString() throws {
    let validated = try TemplateValidator().validate(validRequest(), against: validTemplate())

    #expect(validated.executable == "/usr/bin/curl")
    #expect(validated.risk == .writeOrExternalSend)
    #expect(validated.arguments == [
        .literal("-H"),
        .literal("Authorization: Bearer"),
        .secret(name: "apiToken", reference: try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")),
        .literal("--data"),
        .value(name: "message", value: "hello"),
        .literal("https://api.example.com/send")
    ])
}

private func expectValidationError(
    _ expected: TemplateValidationError,
    performing operation: () throws -> Void
) async {
    do {
        try operation()
        Issue.record("Expected \(expected), but validation succeeded.")
    } catch let error as TemplateValidationError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private func validTemplate() -> ExecutionTemplate {
    ExecutionTemplate(
        id: "send-message",
        executable: "/usr/bin/curl",
        arguments: [
            .literal("-H"),
            .literal("Authorization: Bearer"),
            .secret(name: "apiToken"),
            .literal("--data"),
            .value(name: "message"),
            .literal("https://api.example.com/send")
        ],
        risk: .writeOrExternalSend,
        allowedHosts: ["api.example.com"],
        allowedPaths: ["/v1/send"]
    )
}

private func validRequest() -> ExecutionRequest {
    ExecutionRequest(
        templateID: "send-message",
        executable: "/usr/bin/curl",
        values: ["message": "hello"],
        secrets: ["apiToken": try! SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
        destinationHost: "api.example.com",
        destinationPath: "/v1/send",
        requestedRisk: .writeOrExternalSend
    )
}
