import Testing
import VaultAuthorization
import VaultCore

@Test func safeCatalogMutationsAreSilent() {
    let engine = CatalogMutationPolicyEngine()
    for kind in [
        CatalogMutationKind.createIndex,
        .createEntry,
        .patchMetadata,
        .addMetadataField,
        .createSecretPlaceholder,
        .validate
    ] {
        #expect(engine.evaluate(CatalogMutationDescriptor(kind: kind)) == .silent)
    }
}

@Test func existingSecretMutationsRequireApproval() {
    let engine = CatalogMutationPolicyEngine()
    for kind in [
        CatalogMutationKind.bindExistingSecret,
        .replaceSecret,
        .deleteSecret,
        .deleteSecretBearingEntry,
        .deleteSecretBearingIndex,
        .changeSecretType,
        .changeSecretTarget,
        .changeSecretPolicy,
        .batchMutation,
        .importExport
    ] {
        #expect(engine.evaluate(CatalogMutationDescriptor(kind: kind)) == .approvalRequired)
    }
}

@Test func forbiddenCatalogWritesAreDenied() {
    let engine = CatalogMutationPolicyEngine()
    for kind in [
        CatalogMutationKind.plaintextSecretInCatalog,
        .directManagedFileWrite,
        .forgedSecretReference,
        .agentSelfApproval
    ] {
        #expect(engine.evaluate(CatalogMutationDescriptor(kind: kind)) == .denied)
    }
}

@Test func metadataTargetChangeOnSecretEntryRequiresApproval() {
    let engine = CatalogMutationPolicyEngine()
    #expect(engine.evaluate(CatalogMutationDescriptor(
        kind: .patchMetadata,
        touchesExistingSecret: true,
        changesSecretTarget: true
    )) == .approvalRequired)
}
