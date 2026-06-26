import Foundation
import Testing
@testable import VaultCore

@Test func parsesCanonicalReference() throws {
    let ref = try SecretReference("secret://01JABCDEF0123456789ABCDEFG")
    #expect(ref.description == "secret://01JABCDEF0123456789ABCDEFG")
}

@Test func rejectsMetadataInReference() {
    #expect(throws: SecretReference.Error.self) {
        try SecretReference("secret://password@example.com")
    }
}

@Test func codableRoundTripsReferenceAsCanonicalString() throws {
    let ref = try SecretReference("secret://01JABCDEF0123456789ABCDEFG")

    let encoded = try JSONEncoder().encode(ref)
    let decoded = try JSONDecoder().decode(SecretReference.self, from: encoded)

    #expect(decoded == ref)
    #expect(decoded.description == "secret://01JABCDEF0123456789ABCDEFG")
}
