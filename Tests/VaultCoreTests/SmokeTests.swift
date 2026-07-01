import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 2)
    #expect(VaultFormat.legacyV1 == 1)
}
