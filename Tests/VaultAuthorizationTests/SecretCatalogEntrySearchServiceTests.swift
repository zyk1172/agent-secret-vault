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

@Test func sameDestinationDoesNotMergeDifferentEntries() {
    let result = SecretCatalogEntrySearchService().search(query: "192.168.2.240", limit: 20, document: qnapCatalogDocument())
    let ids = Set(result.matches.map { $0.entry.id })

    #expect(ids == Set([searchAdminID, searchKomgaID, searchSSHID]))
}
