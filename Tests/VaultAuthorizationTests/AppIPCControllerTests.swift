import Foundation
import Testing
@testable import AgentSecretVaultApp

@Test func appIPCControllerPublishesEndpointMetadataWithoutSecrets() throws {
    let metadata = AppIPCController.EndpointMetadata(socketPath: "/tmp/asv.sock")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let encoded = try encoder.encode(metadata)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(json.contains("/tmp/asv.sock"))
    #expect(!json.contains("capability"))
    #expect(!json.contains("token"))
}
