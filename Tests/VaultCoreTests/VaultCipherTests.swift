import CryptoKit
import Foundation
import Testing
@testable import VaultCore

@Test func encryptDecryptRoundTrip() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let record = try cipher.encrypt(
        Data("sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "test",
        policy: .credential,
        masterKey: master
    )

    #expect(try cipher.decrypt(record, masterKey: master) == Data("sensitive".utf8))
}

@Test func tamperedCiphertextFails() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let record = try cipher.encrypt(
        Data("sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "test",
        policy: .credential,
        masterKey: master
    )

    var tamperedCiphertext = record.ciphertext
    tamperedCiphertext[tamperedCiphertext.startIndex] ^= 0x01
    let tampered = EncryptedRecord(
        formatVersion: record.formatVersion,
        id: record.id,
        recordVersion: record.recordVersion,
        ciphertext: tamperedCiphertext,
        nonce: record.nonce,
        tag: record.tag,
        wrappedDataKey: record.wrappedDataKey,
        wrappedDataKeyNonce: record.wrappedDataKeyNonce,
        wrappedDataKeyTag: record.wrappedDataKeyTag,
        label: record.label,
        policy: record.policy,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt
    )

    do {
        _ = try cipher.decrypt(tampered, masterKey: master)
        Issue.record("Expected tampered ciphertext to fail integrity validation.")
    } catch {
        #expect(error as? VaultCryptoError == .integrityFailed)
    }
}

@Test func tamperedPolicyFailsIntegrityValidation() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let record = try cipher.encrypt(
        Data("sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "test",
        policy: .credential,
        masterKey: master
    )

    let tampered = EncryptedRecord(
        formatVersion: record.formatVersion,
        id: record.id,
        recordVersion: record.recordVersion,
        ciphertext: record.ciphertext,
        nonce: record.nonce,
        tag: record.tag,
        wrappedDataKey: record.wrappedDataKey,
        wrappedDataKeyNonce: record.wrappedDataKeyNonce,
        wrappedDataKeyTag: record.wrappedDataKeyTag,
        label: record.label,
        policy: .externalSend,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt
    )

    do {
        _ = try cipher.decrypt(tampered, masterKey: master)
        Issue.record("Expected tampered policy to fail integrity validation.")
    } catch {
        #expect(error as? VaultCryptoError == .integrityFailed)
    }
}

@Test func samePlaintextProducesDifferentCiphertext() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let plaintext = Data("sensitive".utf8)

    let first = try cipher.encrypt(
        plaintext,
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "test",
        policy: .credential,
        masterKey: master
    )
    let second = try cipher.encrypt(
        plaintext,
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "test",
        policy: .credential,
        masterKey: master
    )

    #expect(first.ciphertext != second.ciphertext)
    #expect(first.wrappedDataKey != second.wrappedDataKey)
}
