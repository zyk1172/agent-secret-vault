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

    #expect(record.formatVersion == VaultFormat.current)
    #expect(record.keyDerivationSalt?.count == 32)
    #expect(try cipher.decrypt(record, masterKey: master) == Data("sensitive".utf8))
}

@Test func rebindResealsAuthenticatedMetadataWithoutChangingPlaintext() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let updatedAt = Date(timeIntervalSinceReferenceDate: 2_000)
    let record = try cipher.encrypt(
        Data("sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 3,
        label: "test",
        policy: .credential,
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["ssh"],
        masterKey: master
    )

    let rebound = try cipher.rebind(
        record,
        allowedDestinations: ["qnap.local", "http://192.168.2.240:3000"],
        allowedProtocols: ["ssh", "http"],
        allowedBindings: [
            SecretDestinationBinding(protocolType: .ssh, destination: "qnap.local"),
            SecretDestinationBinding(protocolType: .http, destination: "http://192.168.2.240:3000")
        ],
        masterKey: master,
        updatedAt: updatedAt
    )

    #expect(rebound.recordVersion == 4)
    #expect(rebound.createdAt == record.createdAt)
    #expect(rebound.updatedAt == updatedAt)
    #expect(rebound.allowedDestinations == ["qnap.local", "http://192.168.2.240:3000"])
    #expect(rebound.allowedProtocols == ["ssh", "http"])
    #expect(rebound.allowedBindings == [
        SecretDestinationBinding(protocolType: .ssh, destination: "qnap.local"),
        SecretDestinationBinding(protocolType: .http, destination: "http://192.168.2.240:3000")
    ])
    #expect(try cipher.decrypt(rebound, masterKey: master) == Data("sensitive".utf8))

    let tampered = EncryptedRecord(
        formatVersion: rebound.formatVersion,
        id: rebound.id,
        recordVersion: rebound.recordVersion,
        ciphertext: rebound.ciphertext,
        nonce: rebound.nonce,
        tag: rebound.tag,
        wrappedDataKey: rebound.wrappedDataKey,
        wrappedDataKeyNonce: rebound.wrappedDataKeyNonce,
        wrappedDataKeyTag: rebound.wrappedDataKeyTag,
        keyDerivationSalt: rebound.keyDerivationSalt,
        label: rebound.label,
        policy: rebound.policy,
        allowedDestinations: ["qnap.local"],
        allowedProtocols: rebound.allowedProtocols,
        policyBindingVersion: rebound.policyBindingVersion,
        createdAt: rebound.createdAt,
        updatedAt: rebound.updatedAt
    )
    #expect(throws: VaultCryptoError.integrityFailed) {
        _ = try cipher.decrypt(tampered, masterKey: master)
    }
}

@Test func decryptsLegacyV1RecordAfterFormatBump() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let legacy = try cipher.encrypt(
        Data("legacy sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "legacy",
        policy: .credential,
        masterKey: master,
        formatVersion: VaultFormat.legacyV1
    )

    #expect(legacy.formatVersion == VaultFormat.legacyV1)
    #expect(legacy.keyDerivationSalt == nil)
    #expect(try cipher.decrypt(legacy, masterKey: master) == Data("legacy sensitive".utf8))
}

@Test func typedBindingsRemainAuthenticatedOnLegacyFormatRecords() throws {
    let master = SymmetricKey(size: .bits256)
    let cipher = VaultCipher()
    let binding = SecretDestinationBinding(protocolType: .http, destination: "http://nas.local:3000")
    let legacy = try cipher.encrypt(
        Data("legacy sensitive".utf8),
        id: "01JABCDEF0123456789ABCDEFG",
        version: 1,
        label: "legacy",
        policy: .credential,
        allowedBindings: [binding],
        masterKey: master,
        formatVersion: VaultFormat.legacyV1
    )

    #expect(try cipher.decrypt(legacy, masterKey: master) == Data("legacy sensitive".utf8))

    let tampered = EncryptedRecord(
        formatVersion: legacy.formatVersion,
        id: legacy.id,
        recordVersion: legacy.recordVersion,
        ciphertext: legacy.ciphertext,
        nonce: legacy.nonce,
        tag: legacy.tag,
        wrappedDataKey: legacy.wrappedDataKey,
        wrappedDataKeyNonce: legacy.wrappedDataKeyNonce,
        wrappedDataKeyTag: legacy.wrappedDataKeyTag,
        keyDerivationSalt: legacy.keyDerivationSalt,
        label: legacy.label,
        policy: legacy.policy,
        allowedBindings: [SecretDestinationBinding(protocolType: .http, destination: "http://attacker.local:3000")],
        policyBindingVersion: legacy.policyBindingVersion,
        createdAt: legacy.createdAt,
        updatedAt: legacy.updatedAt
    )
    #expect(throws: VaultCryptoError.integrityFailed) {
        _ = try cipher.decrypt(tampered, masterKey: master)
    }
}

@Test func missingV2DerivationSaltFailsClosed() throws {
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
    let missingSalt = EncryptedRecord(
        formatVersion: record.formatVersion,
        id: record.id,
        recordVersion: record.recordVersion,
        ciphertext: record.ciphertext,
        nonce: record.nonce,
        tag: record.tag,
        wrappedDataKey: record.wrappedDataKey,
        wrappedDataKeyNonce: record.wrappedDataKeyNonce,
        wrappedDataKeyTag: record.wrappedDataKeyTag,
        keyDerivationSalt: nil,
        label: record.label,
        policy: record.policy,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt
    )

    do {
        _ = try cipher.decrypt(missingSalt, masterKey: master)
        Issue.record("Expected missing v2 key derivation salt to fail.")
    } catch {
        #expect(error as? VaultCryptoError == .integrityFailed)
    }
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
