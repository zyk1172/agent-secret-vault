import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 1)
}
