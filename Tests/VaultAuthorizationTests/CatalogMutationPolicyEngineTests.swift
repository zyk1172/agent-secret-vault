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
        .importExport
    ] {
        #expect(engine.evaluate(CatalogMutationDescriptor(kind: kind)) == .approvalRequired)
    }

    #expect(engine.evaluate(CatalogMutationDescriptor(
        kind: .batchMutation,
        semanticKinds: [.updateMetadataField, .bindExistingSecret]
    )) == .approvalRequired)
}

@Test func forbiddenCatalogWritesAreDenied() {
    let engine = CatalogMutationPolicyEngine()
    for kind in [
        CatalogMutationKind.plaintextSecretInCatalog,
        .forgedSecretReference,
        .agentSelfApproval
    ] {
        #expect(engine.evaluate(CatalogMutationDescriptor(kind: kind)) == .denied)
    }

    #expect(engine.evaluate(CatalogMutationDescriptor(kind: .directManagedFileWrite)) == .silent)
}

@Test func writerTransportDoesNotChangeSemanticRisk() {
    let engine = CatalogMutationPolicyEngine()
    let safe = CatalogSemanticDiff(changes: [.init(kind: .updateEntryMetadata)])
    let high = CatalogSemanticDiff(changes: [.init(kind: .replaceSecret, oldSecretRef: "secret://old", newSecretRef: "secret://new")])

    #expect(engine.evaluate(safe, transport: .directManagedFileWrite) == .silent)
    #expect(engine.evaluate(safe, transport: .batchMutation) == .silent)
    #expect(engine.evaluate(high, transport: .directManagedFileWrite) == .approvalRequired)
    #expect(engine.evaluate(high, transport: .batchMutation) == .approvalRequired)
}

@Test func metadataTargetChangeOnSecretEntryRequiresApproval() {
    let engine = CatalogMutationPolicyEngine()
    #expect(engine.evaluate(CatalogMutationDescriptor(
        kind: .patchMetadata,
        touchesExistingSecret: true,
        changesSecretTarget: true
    )) == .approvalRequired)
}
