import Foundation
import Security

public enum RandomBytes {
    public static func generate(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw VaultCryptoError.randomGenerationFailed
        }

        return Data(bytes)
    }
}
