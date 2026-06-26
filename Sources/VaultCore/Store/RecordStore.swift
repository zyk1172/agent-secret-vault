public protocol RecordStore: Sendable {
    func save(_ record: EncryptedRecord) async throws
    func latest(id: String) async throws -> EncryptedRecord
    func versions(id: String) async throws -> [Int]
}
