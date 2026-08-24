import Foundation
import Testing
import VaultCore
@testable import VaultService

private let qnapUsernameReference = "secret://0123456789ABCDEFGHJKMNPQRS"
private let qnapPasswordReference = "secret://0123456789ABCDEFGHJKMNPQRT"
private let qnapTokenReference = "secret://0123456789ABCDEFGHJKMNPQRV"

private let qnapGroupID = "group-qnap"

@Test func catalogSearchFindsQNAPByServiceDestinationAndChinesePurpose() throws {
    let service = SecretCatalogService(selectionManifestURL: URL(filePath: "/tmp/svlt-test-selection.json"))
    let entries = [
        LegacySecretCatalogEntry(
            reference: qnapUsernameReference,
            service: "QNAP",
            field: .username,
            label: "QNAP 用户名",
            destinations: ["192.168.2.240"],
            purpose: "媒体管理与备份",
            groupID: qnapGroupID,
            contextTerms: ["NAS", "QNAP"]
        ),
        LegacySecretCatalogEntry(
            reference: qnapPasswordReference,
            service: "QNAP",
            field: .password,
            label: "QNAP 密码",
            destinations: ["192.168.2.240"],
            purpose: "媒体管理与备份",
            groupID: qnapGroupID,
            contextTerms: ["NAS", "QNAP"]
        ),
        LegacySecretCatalogEntry(
            reference: qnapTokenReference,
            service: "Cloud API",
            field: .token,
            label: "同步 Token",
            destinations: ["api.example.local"],
            purpose: "自动同步",
            groupID: "group-cloud",
            contextTerms: ["Cloud API"]
        )
    ]
    let metadata = [
        SecretCatalogRecordMetadata(
            reference: qnapUsernameReference,
            policy: .credential,
            label: "QNAP credential",
            allowedDestinations: ["192.168.2.240"]
        ),
        SecretCatalogRecordMetadata(
            reference: qnapPasswordReference,
            policy: .credential,
            label: "QNAP credential",
            allowedDestinations: ["192.168.2.240"]
        ),
        SecretCatalogRecordMetadata(
            reference: qnapTokenReference,
            policy: .externalSend,
            label: "Cloud token",
            allowedDestinations: ["api.example.local"]
        )
    ]

    let byService = service.search(query: "qnap", field: nil, limit: 10, entries: entries, metadata: metadata)
    #expect(byService.status == .found)
    #expect(Set(byService.matches.map(\.reference)) == Set([qnapUsernameReference, qnapPasswordReference]))
    #expect(byService.matches.allSatisfy { $0.policy == .credential })
    #expect(byService.matches.allSatisfy { $0.destinations == ["192.168.2.240"] })
    #expect(byService.matches.allSatisfy { $0.groupID == qnapGroupID })

    let byCaseInsensitiveService = service.search(query: "QNAP", field: nil, limit: 10, entries: entries, metadata: metadata)
    #expect(byCaseInsensitiveService.matches == byService.matches)

    let byDestination = service.search(query: "192.168.2.240", field: nil, limit: 10, entries: entries, metadata: metadata)
    #expect(Set(byDestination.matches.map(\.reference)) == Set([qnapUsernameReference, qnapPasswordReference]))

    let byPurpose = service.search(query: "媒体管理", field: nil, limit: 10, entries: entries, metadata: metadata)
    #expect(Set(byPurpose.matches.map(\.reference)) == Set([qnapUsernameReference, qnapPasswordReference]))

    let passwordOnly = service.search(query: "QNAP", field: .password, limit: 10, entries: entries, metadata: metadata)
    #expect(passwordOnly.matches.map(\.reference) == [qnapPasswordReference])
}

@Test func catalogSearchDeduplicatesCatalogAndRecordMetadataAndDoesNotExposePlaintextOrPaths() throws {
    let service = SecretCatalogService(selectionManifestURL: URL(filePath: "/Users/example/敏感信息.md"))
    let canary = "ASV_CANARY_CATALOG_PLAINTEXT_DO_NOT_PERSIST"
    let entry = LegacySecretCatalogEntry(
        reference: qnapPasswordReference,
        service: "QNAP",
        field: .password,
        label: "QNAP 密码",
        destinations: ["192.168.2.240"],
        purpose: "媒体管理",
        groupID: qnapGroupID,
        contextTerms: ["NAS"]
    )
    let duplicateEntry = LegacySecretCatalogEntry(
        reference: qnapPasswordReference,
        service: "QNAP",
        field: .password,
        label: nil,
        destinations: [],
        purpose: nil,
        groupID: qnapGroupID,
        contextTerms: []
    )
    let result = service.search(
        query: "NAS",
        field: nil,
        limit: 10,
        entries: [entry, duplicateEntry],
        metadata: [
            SecretCatalogRecordMetadata(
                reference: qnapPasswordReference,
                policy: .credential,
                label: canary,
                allowedDestinations: ["192.168.2.240"]
            )
        ]
    )

    #expect(result.status == .found)
    #expect(result.matches.count == 1)
    #expect(result.matches[0].reference == qnapPasswordReference)
    #expect(result.matches[0].label == "QNAP 密码")
    let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
    #expect(!encoded.contains(canary))
    #expect(!encoded.contains("/Users/example/敏感信息.md"))
    #expect(!encoded.contains("line"))
    #expect(!encoded.contains("masterKey"))
    #expect(!encoded.contains("plaintext"))
}

@Test func catalogSearchRejectsEmptyQueryReportsNotFoundAndClampsLimit() throws {
    let service = SecretCatalogService(selectionManifestURL: URL(filePath: "/tmp/svlt-test-selection.json"))
    let empty = service.search(query: "  ", field: nil, limit: 10, entries: [], metadata: [])
    #expect(empty.status == .invalidQuery)
    #expect(empty.matches.isEmpty)

    let missing = service.search(query: "does-not-exist", field: nil, limit: 10, entries: [], metadata: [])
    #expect(missing.status == .notFound)

    let allowedCharacters = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    let prefix = "0123456789ABCDEFGHJKMNPQ"
    let references = (0..<25).map { index in
        "secret://\(prefix)\(allowedCharacters[index])\(allowedCharacters[(index + 1) % allowedCharacters.count])"
    }
    let entries = references.enumerated().map { index, reference in
        LegacySecretCatalogEntry(
            reference: reference,
            service: "Service-\(index)",
            field: .other,
            label: "Service-\(index)",
            contextTerms: ["bulk"]
        )
    }
    let result = service.search(query: "service", field: nil, limit: 999, entries: entries, metadata: [])
    #expect(result.status == .found)
    #expect(result.matches.count == 20)
    #expect(Set(result.matches.map(\.reference)).count == 20)
}

@Test func catalogSearchUsesExactServiceRankingBeforeContextMatches() throws {
    let service = SecretCatalogService(selectionManifestURL: URL(filePath: "/tmp/svlt-test-selection.json"))
    let exact = LegacySecretCatalogEntry(
        reference: qnapPasswordReference,
        service: "QNAP",
        field: .password,
        label: "NAS password",
        contextTerms: ["device"]
    )
    let contextOnly = LegacySecretCatalogEntry(
        reference: qnapUsernameReference,
        service: "Other service",
        field: .username,
        label: "Other login",
        contextTerms: ["QNAP"]
    )

    let result = service.search(
        query: "qnap",
        field: nil,
        limit: 10,
        entries: [contextOnly, exact],
        metadata: []
    )

    #expect(result.matches.map(\.reference) == [qnapPasswordReference, qnapUsernameReference])
}
