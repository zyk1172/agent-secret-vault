import Foundation
import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 2)
    #expect(VaultFormat.legacyV1 == 1)
}

@Test func explicitPlaintextOverrideHasNoSecretPayload() throws {
    let override = ExplicitPlaintextOverride.userSuppliedForCurrentOperation

    #expect(override.scope == .userExplicitPlaintext)
    #expect(override.source == .userCurrentRequest)
    #expect(override == .userSuppliedForCurrentOperation)

    let encoded = try JSONEncoder().encode(override)
    let decoded = try JSONDecoder().decode(ExplicitPlaintextOverride.self, from: encoded)
    #expect(decoded == override)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("plaintext-value"))
}

@Test func explicitNoSVLTSelectionAlsoUsesUserPlaintextScope() {
    let selection = SVLTCredentialSelection.userPlaintext(.explicitlySelectedNoSVLT)

    #expect(selection.scope == .userExplicitPlaintext)
    #expect(selection.source == .userCurrentRequest)
    #expect(selection.shouldSearchSVLT == false)
    #expect(selection.shouldInvokeSVLT == false)
}

@Test func credentialSelectionIsPerOperationAndDoesNotInheritPreviousSVLT() {
    let previous = SVLTCredentialSelection.svlt
    let current = SVLTCredentialSelection.userPlaintext(.userSuppliedForCurrentOperation)

    #expect(previous.scope == .svltManagedOperation)
    #expect(current.scope == .userExplicitPlaintext)
    #expect(current.source == .userCurrentRequest)
    #expect(current.shouldSearchSVLT == false)
}

@Test func credentialSelectionUsesTheCurrentSourceForEveryOperation() {
    let previousExternal = SVLTCredentialSelection.externalProvider
    let currentSVLT = SVLTCredentialSelection.svlt

    #expect(previousExternal.scope == .externalProviderOperation)
    #expect(currentSVLT.scope == .svltManagedOperation)
    #expect(currentSVLT.source == .explicitSVLTReference)
    #expect(currentSVLT.shouldInvokeSVLT)
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
