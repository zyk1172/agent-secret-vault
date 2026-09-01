import Testing
import VaultCore
import VaultService

private let searchIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let searchAdminID = "0123456789ABCDEFGHJKMNPQRT"
private let searchKomgaID = "0123456789ABCDEFGHJKMNPQRV"
private let searchSSHID = "0123456789ABCDEFGHJKMNPQRW"

private func qnapCatalogDocument() -> SecretCatalogDocument {
    SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: searchIndexID, title: "QNAP", aliases: ["NAS"], tags: ["设备"])],
        entries: [
            SecretCatalogEntry(
                id: searchAdminID,
                indexId: searchIndexID,
                title: "QNAP 管理后台登录",
                endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
                fields: [
                    SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
                    SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: "secret://0123456789ABCDEFGHJKMNPQRS")
                ],
                notes: "QNAP 主机管理账号",
                tags: ["QNAP", "管理"]
            ),
            SecretCatalogEntry(
                id: searchKomgaID,
                indexId: searchIndexID,
                title: "Komga 漫画服务器登录",
                aliases: ["漫画服务器"],
                endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 25600)],
                fields: [
                    SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("zyk")),
                    SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: "secret://0123456789ABCDEFGHJKMNPQRT")
                ],
                tags: ["QNAP", "Komga", "漫画"]
            ),
            SecretCatalogEntry(
                id: searchSSHID,
                indexId: searchIndexID,
                title: "SSH 登录",
                endpoints: [CatalogEndpoint(type: "ssh", host: "192.168.2.240", port: 22)],
                fields: [
                    SecretCatalogFieldValue(
                        key: "username",
                        label: "用户名",
                        type: .text,
                        agentVisible: false,
                        searchable: true,
                        value: .string("hidden-admin")
                    ),
                    SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: "secret://0123456789ABCDEFGHJKMNPQRV")
                ],
                tags: ["QNAP", "SSH"]
            )
        ]
    )
}

@Test func entrySearchReturnsCompleteVisibleContextForQNAP() {
    let result = SecretCatalogEntrySearchService().search(query: "QNAP", limit: 20, document: qnapCatalogDocument())

    #expect(result.status == .found)
    #expect(result.matches.count == 3)
    #expect(result.matches.contains { match in
        match.entry.title == "QNAP 管理后台登录"
            && match.entry.fields.contains { $0.key == "username" && $0.value == .string("admin") }
            && match.entry.fields.contains { $0.key == "password" && $0.secretRef != nil && $0.value == nil }
    })
    #expect(result.matches.contains { $0.entry.title == "Komga 漫画服务器登录" })
}

@Test func entrySearchSupportsKomgaHostAndHiddenSearchableMetadata() {
    let service = SecretCatalogEntrySearchService()
    let document = qnapCatalogDocument()
    let komga = service.search(query: "Komga", document: document)
    let host = service.search(query: "192.168.2.240", limit: 20, document: document)
    let hidden = service.search(query: "hidden-admin", document: document)

    #expect(komga.matches.count == 1)
    #expect(komga.matches.first?.entry.fields.contains { $0.value == .string("zyk") } == true)
    #expect(host.matches.count == 3)
    #expect(hidden.matches.count == 1)
    #expect(hidden.matches[0].entry.fields.contains { $0.key == "username" } == false)
}

@Test func entrySearchFindsUserFacingSecretFieldLabelAndKeepsStableKeyFallback() {
    let indexID = "0123456789ABCDEFGHJKMNPQRY"
    let entryID = "0123456789ABCDEFGHJKMNPQRZ"
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: indexID, title: "API")],
        entries: [SecretCatalogEntry(
            id: entryID,
            indexId: indexID,
            title: "NewAPI",
            fields: [SecretCatalogFieldValue(
                key: "field4",
                label: "API Token",
                type: .secret,
                searchable: true,
                secretRef: "secret://0123456789ABCDEFGHJKMNPQRS"
            )]
        )]
    )
    let service = SecretCatalogEntrySearchService()

    let byLabel = service.search(query: "API Token", document: document)
    let byKey = service.search(query: "field4", document: document)

    #expect(byLabel.status == .found)
    #expect(byLabel.matches.count == 1)
    #expect(byLabel.matches[0].entry.id == entryID)
    #expect(byLabel.matches[0].entry.fields == [SecretCatalogFieldMatch(
        key: "field4",
        label: "API Token",
        type: .secret,
        secretRef: "secret://0123456789ABCDEFGHJKMNPQRS"
    )])
    #expect(byKey.status == .found)
    #expect(byKey.matches.count == 1)
    #expect(byKey.matches[0].entry.id == entryID)
}

@Test func entrySearchStructuredFieldFilterUsesKeyAndUserFacingLabel() {
    let indexID = "0123456789ABCDEFGHJKMNPQRY"
    let entryID = "0123456789ABCDEFGHJKMNPQRZ"
    let legacyEntryID = "0123456789ABCDEFGHJKMNPQSA"
    let document = SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: indexID, title: "API")],
        entries: [
            SecretCatalogEntry(
                id: entryID,
                indexId: indexID,
                title: "NewAPI",
                fields: [
                    SecretCatalogFieldValue(
                        key: "field4",
                        label: "密码",
                        type: .secret,
                        secretRef: "secret://0123456789ABCDEFGHJKMNPQRS"
                    ),
                    SecretCatalogFieldValue(
                        key: "field5",
                        label: "API 密钥",
                        type: .secret,
                        secretRef: "secret://0123456789ABCDEFGHJKMNPQRT"
                    )
                ]
            ),
            SecretCatalogEntry(
                id: legacyEntryID,
                indexId: indexID,
                title: "Legacy",
                fields: [
                    SecretCatalogFieldValue(
                        key: "password",
                        label: "登录口令",
                        type: .secret,
                        secretRef: "secret://0123456789ABCDEFGHJKMNPQRV"
                    )
                ]
            )
        ]
    )
    let service = SecretCatalogEntrySearchService()

    let passwordByLabel = service.search(
        query: "NewAPI",
        field: .password,
        document: document
    )
    let apiKeyByLabel = service.search(
        query: "NewAPI",
        field: .apiKey,
        document: document
    )
    let legacyPasswordByKey = service.search(
        query: "Legacy",
        field: .password,
        document: document
    )

    #expect(passwordByLabel.status == .found)
    #expect(passwordByLabel.matches.map { $0.entry.id } == [entryID])
    #expect(apiKeyByLabel.status == .found)
    #expect(apiKeyByLabel.matches.map { $0.entry.id } == [entryID])
    #expect(legacyPasswordByKey.status == .found)
    #expect(legacyPasswordByKey.matches.map { $0.entry.id } == [legacyEntryID])
}

@Test func sameDestinationDoesNotMergeDifferentEntries() {
    let result = SecretCatalogEntrySearchService().search(query: "192.168.2.240", limit: 20, document: qnapCatalogDocument())
    let ids = Set(result.matches.map { $0.entry.id })

    #expect(ids == Set([searchAdminID, searchKomgaID, searchSSHID]))
}

@Test func catalogBrowsingIncludesEmptyIndexesAndProjectsEntriesByIndex() {
    let emptyIndexID = "0123456789ABCDEFGHJKMNPQRY"
    let document = SecretCatalogDocument(
        indexes: [
            SecretCatalogIndex(id: searchIndexID, title: "QNAP"),
            SecretCatalogIndex(id: emptyIndexID, title: "空分组")
        ],
        entries: qnapCatalogDocument().entries
    )
    let service = SecretCatalogEntrySearchService()

    let indexes = service.listIndexes(document: document)
    #expect(indexes.map(\.title) == ["QNAP", "空分组"])
    #expect(indexes.first?.entryCount == 3)
    #expect(indexes.last?.entryCount == 0)

    let emptyEntries = service.listEntries(indexID: emptyIndexID, document: document, revision: 7)
    #expect(emptyEntries.status == .found)
    #expect(emptyEntries.entries.isEmpty)
    #expect(emptyEntries.revision == 7)
}
