import Foundation
import VaultCore

public struct SensitiveCatalogPresetField: Identifiable, Equatable, Sendable {
    public let id: String
    public let key: String
    public let label: String
    public let type: SecretCatalogFieldType
    public let agentVisible: Bool
    public let searchable: Bool

    public init(
        key: String,
        label: String,
        type: SecretCatalogFieldType,
        agentVisible: Bool = true,
        searchable: Bool = true
    ) {
        self.id = key
        self.key = key
        self.label = label
        self.type = type
        self.agentVisible = agentVisible
        self.searchable = searchable
    }
}

public struct SensitiveCatalogEntryPreset: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let fields: [SensitiveCatalogPresetField]

    public init(id: String, title: String, fields: [SensitiveCatalogPresetField]) {
        self.id = id
        self.title = title
        self.fields = fields
    }

    public func makeFields() -> [SecretCatalogFieldValue] {
        fields.map {
            SecretCatalogFieldValue(
                key: $0.key,
                label: $0.label,
                type: $0.type,
                agentVisible: $0.agentVisible,
                searchable: $0.searchable
            )
        }
    }

    /// The App starts a manually-created Entry with one editable field.  The
    /// remaining preset fields stay available as a reference for Agent/API
    /// creation and can be added from the Entry editor when needed.
    public func makeInitialField() -> SecretCatalogFieldValue {
        let presetField = fields.first ?? SensitiveCatalogPresetField(
            key: "value",
            label: "值",
            type: .text
        )
        return SecretCatalogFieldValue(
            key: presetField.key,
            label: presetField.label,
            type: presetField.type,
            agentVisible: presetField.agentVisible,
            searchable: presetField.searchable
        )
    }

    public static let all: [Self] = [
        Self(id: "credential", title: "账号密码", fields: [
            .init(key: "service", label: "服务", type: .text),
            .init(key: "host", label: "地址", type: .host),
            .init(key: "username", label: "用户名", type: .text),
            .init(key: "password", label: "密码", type: .secret, searchable: false),
            .init(key: "note", label: "备注", type: .multiline)
        ]),
        Self(id: "api-token", title: "API / Token", fields: [
            .init(key: "service", label: "服务", type: .text),
            .init(key: "baseURL", label: "Base URL", type: .url),
            .init(key: "token", label: "API Key / Token", type: .secret, searchable: false),
            .init(key: "header", label: "Header", type: .text),
            .init(key: "note", label: "备注", type: .multiline)
        ]),
        Self(id: "oauth", title: "OAuth", fields: [
            .init(key: "clientID", label: "Client ID", type: .text),
            .init(key: "clientSecret", label: "Client Secret", type: .secret, searchable: false),
            .init(key: "tokenURL", label: "Token URL", type: .url),
            .init(key: "scope", label: "Scope", type: .list)
        ]),
        Self(id: "ssh", title: "SSH / SFTP", fields: [
            .init(key: "host", label: "主机", type: .host),
            .init(key: "port", label: "端口", type: .port),
            .init(key: "username", label: "用户名", type: .text),
            .init(key: "password", label: "密码", type: .secret, searchable: false),
            .init(key: "privateKey", label: "私钥", type: .secret, searchable: false),
            .init(key: "note", label: "备注", type: .multiline)
        ]),
        Self(id: "database", title: "数据库", fields: [
            .init(key: "databaseType", label: "类型", type: .text),
            .init(key: "host", label: "Host", type: .host),
            .init(key: "port", label: "Port", type: .port),
            .init(key: "database", label: "Database", type: .text),
            .init(key: "username", label: "Username", type: .text),
            .init(key: "password", label: "Password", type: .secret, searchable: false)
        ]),
        Self(id: "email", title: "邮箱", fields: [
            .init(key: "address", label: "邮箱地址", type: .text),
            .init(key: "imap", label: "IMAP", type: .host),
            .init(key: "smtp", label: "SMTP", type: .host),
            .init(key: "username", label: "用户名", type: .text),
            .init(key: "password", label: "密码", type: .secret, searchable: false)
        ]),
        Self(id: "nas-server", title: "NAS / 服务器", fields: [
            .init(key: "host", label: "主机", type: .host),
            .init(key: "adminURL", label: "管理地址", type: .url),
            .init(key: "username", label: "用户名", type: .text),
            .init(key: "password", label: "密码", type: .secret, searchable: false),
            .init(key: "note", label: "备注", type: .multiline)
        ]),
        Self(id: "cloud", title: "云服务", fields: [
            .init(key: "provider", label: "Provider", type: .text),
            .init(key: "account", label: "Account", type: .text),
            .init(key: "accessKey", label: "Access Key", type: .text),
            .init(key: "secretKey", label: "Secret Key", type: .secret, searchable: false),
            .init(key: "region", label: "Region", type: .text)
        ]),
        Self(id: "wifi", title: "Wi-Fi / 网络", fields: [
            .init(key: "ssid", label: "SSID", type: .text),
            .init(key: "username", label: "用户名", type: .text),
            .init(key: "password", label: "密码", type: .secret, searchable: false),
            .init(key: "gateway", label: "网关", type: .host),
            .init(key: "note", label: "备注", type: .multiline)
        ]),
        Self(id: "certificate", title: "证书 / 私钥", fields: [
            .init(key: "domain", label: "域名", type: .host),
            .init(key: "certificate", label: "Certificate", type: .multiline),
            .init(key: "privateKey", label: "Private Key", type: .secret, searchable: false),
            .init(key: "passphrase", label: "Passphrase", type: .secret, searchable: false)
        ]),
        Self(id: "totp", title: "TOTP / 恢复码", fields: [
            .init(key: "account", label: "账号", type: .text),
            .init(key: "totpSecret", label: "TOTP Secret", type: .secret, searchable: false),
            .init(key: "recoveryCodes", label: "Recovery Codes", type: .secret, searchable: false)
        ]),
        Self(id: "custom", title: "通用自定义", fields: [])
    ]
}
