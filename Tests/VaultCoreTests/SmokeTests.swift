import Foundation
import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 2)
    #expect(VaultFormat.legacyV1 == 1)
}

@Test func explicitPlaintextOverrideHasNoSecretPayloadAndIsValid() throws {
    let override = ExplicitPlaintextOverride()

    #expect(override.scope == .userExplicitPlaintext)
    #expect(override.source == .userCurrentRequest)
    #expect(override.isValid)

    let encoded = try JSONEncoder().encode(override)
    let decoded = try JSONDecoder().decode(ExplicitPlaintextOverride.self, from: encoded)
    #expect(decoded == override)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("plaintext-value"))
}

@Test func explicitNoSVLTSelectionAlsoUsesUserPlaintextScope() {
    let scope = SVLTCredentialSelection.scope(
        userSuppliedPlaintext: false,
        userExplicitlyRequestedPlaintext: true,
        userExplicitlySelectedNoSVLT: true
    )

    #expect(scope == .userExplicitPlaintext)
}

@Test func explicitSVLTSelectionWinsOnlyWhenUserAlsoSelectsSVLT() {
    let directScope = SVLTCredentialSelection.scope(
        userSuppliedPlaintext: true,
        userExplicitlyRequestedPlaintext: true
    )
    let managedScope = SVLTCredentialSelection.scope(
        userSuppliedPlaintext: true,
        userExplicitlyRequestedPlaintext: true,
        userExplicitlySelectedSVLT: true
    )

    #expect(directScope == .userExplicitPlaintext)
    #expect(managedScope == .svltManagedOperation)
}

@Test func SVLTDoesNotCompareIndependentUserPlaintextWithManagedSecret() {
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .userExplicitPlaintext,
        approvedSVLTOperation: false
    ))
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .externalProviderCredential,
        approvedSVLTOperation: false
    ))
    #expect(!SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .svltDerivedPlaintext,
        approvedSVLTOperation: false
    ))
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .svltDerivedPlaintext,
        approvedSVLTOperation: true
    ))
}
