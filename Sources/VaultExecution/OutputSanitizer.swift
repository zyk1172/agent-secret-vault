import CryptoKit
import Foundation

public enum OutputQuarantineReason: String, Codable, Equatable, Sendable {
    case binaryOutput
    case invalidUTF8
    case emptySecretMaterial
    case encodedSecretVariantDetected
}

public enum SanitizedProcessResult: Equatable, Sendable {
    case sanitized(ProcessResult)
    case quarantined(reason: OutputQuarantineReason)
}

/// A non-reversible guard retained by a live SSH transport so a reused
/// ControlMaster channel can still be checked for secret leakage without
/// resolving the password again. It contains only a digest and byte length.
public struct SecretOutputFingerprint: Equatable, Sendable {
    public let byteCount: Int
    public let digest: Data

    public init(byteCount: Int, digest: Data) {
        self.byteCount = byteCount
        self.digest = digest
    }
}

public struct OutputSanitizer: Sendable {
    private static let maxPercentDecodeDepth = 2
    private static let maxPercentDecodableOutputBytes = 1_048_576
    private let redaction = "[REDACTED_SECRET]"

    public init() {}

    public func sanitize(
        _ result: ProcessResult,
        secrets: [Data]
    ) -> SanitizedProcessResult {
        guard secrets.allSatisfy({ !$0.isEmpty }) else {
            return .quarantined(reason: .emptySecretMaterial)
        }

        guard let stdout = String(data: result.stdout, encoding: .utf8),
              let stderr = String(data: result.stderr, encoding: .utf8) else {
            return .quarantined(reason: .invalidUTF8)
        }

        guard !Self.containsBinaryControlCharacters(stdout),
              !Self.containsBinaryControlCharacters(stderr) else {
            return .quarantined(reason: .binaryOutput)
        }

        let secretStrings = secrets.compactMap { String(data: $0, encoding: .utf8) }
        guard secretStrings.count == secrets.count else {
            return .quarantined(reason: .invalidUTF8)
        }

        guard !containsEncodedSecretVariant(in: stdout, secrets: secrets, secretStrings: secretStrings),
              !containsEncodedSecretVariant(in: stderr, secrets: secrets, secretStrings: secretStrings) else {
            return .quarantined(reason: .encodedSecretVariantDetected)
        }

        let orderedSecrets = secretStrings.sorted {
            if $0.count == $1.count {
                return $0 < $1
            }

            return $0.count > $1.count
        }

        let redactedStdout = redact(orderedSecrets, in: stdout)
        let redactedStderr = redact(orderedSecrets, in: stderr)

        return .sanitized(ProcessResult(
            exitCode: result.exitCode,
            stdout: Data(redactedStdout.utf8),
            stderr: Data(redactedStderr.utf8)
        ))
    }

    /// Checks output using digests retained by an SSH session. A match is
    /// quarantined because the plaintext is intentionally unavailable for
    /// in-place redaction on a reused transport.
    public func sanitize(
        _ result: ProcessResult,
        fingerprints: [SecretOutputFingerprint]
    ) -> SanitizedProcessResult {
        guard let stdout = String(data: result.stdout, encoding: .utf8),
              let stderr = String(data: result.stderr, encoding: .utf8)
        else {
            return .quarantined(reason: .invalidUTF8)
        }
        guard !Self.containsBinaryControlCharacters(stdout),
              !Self.containsBinaryControlCharacters(stderr)
        else {
            return .quarantined(reason: .binaryOutput)
        }
        guard !containsFingerprint(in: stdout, fingerprints: fingerprints),
              !containsFingerprint(in: stderr, fingerprints: fingerprints)
        else {
            return .quarantined(reason: .encodedSecretVariantDetected)
        }
        return .sanitized(result)
    }

    public static func fingerprints(for secret: Data) -> [SecretOutputFingerprint] {
        fingerprints(for: [secret])
    }

    private static func fingerprints(for secrets: [Data]) -> [SecretOutputFingerprint] {
        var values: [SecretOutputFingerprint] = []
        for secret in secrets where !secret.isEmpty {
            appendFingerprint(for: secret, to: &values)
            if let string = String(data: secret, encoding: .utf8) {
                let variants = [
                    Data(secret.base64EncodedString().utf8),
                    Data(string.addingPercentEncoding(withAllowedCharacters: .alphanumerics)?.utf8 ?? string.utf8),
                    Data(secret.map { String(format: "%02x", $0) }.joined().utf8),
                    Data(secret.map { String(format: "%02X", $0) }.joined().utf8)
                ]
                for variant in variants where variant != secret {
                    appendFingerprint(for: variant, to: &values)
                }
            }
        }
        return values
    }

    private static func appendFingerprint(
        for value: Data,
        to values: inout [SecretOutputFingerprint]
    ) {
        let fingerprint = SecretOutputFingerprint(
            byteCount: value.count,
            digest: Data(SHA256.hash(data: value))
        )
        if !values.contains(fingerprint) {
            values.append(fingerprint)
        }
    }

    private func redact(_ secrets: [String], in output: String) -> String {
        secrets.reduce(output) { partial, secret in
            partial.replacingOccurrences(of: secret, with: redaction)
        }
    }

    private func containsEncodedSecretVariant(
        in output: String,
        secrets: [Data],
        secretStrings: [String]
    ) -> Bool {
        zip(secrets, secretStrings).contains { secretData, secretString in
            if encodedVariants(for: secretData, secretString: secretString).contains(where: output.contains) {
                return true
            }
            return containsPercentDecodedSecret(in: output, secret: secretString)
        }
    }

    /// Detect percent-encoded copies without trying to enumerate every
    /// possible mixed-case escape spelling. Decoding is deliberately bounded
    /// so attacker-controlled output cannot turn this check into unbounded
    /// work or recursive canonicalization.
    private func containsPercentDecodedSecret(in output: String, secret: String) -> Bool {
        guard output.utf8.count <= Self.maxPercentDecodableOutputBytes else {
            return false
        }

        var candidate = output
        for _ in 0..<Self.maxPercentDecodeDepth {
            guard let decoded = candidate.removingPercentEncoding,
                  decoded != candidate else {
                return false
            }
            if decoded.contains(secret) {
                return true
            }
            candidate = decoded
        }
        return false
    }

    private func containsFingerprint(
        in output: String,
        fingerprints: [SecretOutputFingerprint]
    ) -> Bool {
        guard !fingerprints.isEmpty else { return false }
        let bytes = Data(output.utf8)
        for fingerprint in fingerprints {
            guard fingerprint.byteCount > 0, fingerprint.byteCount <= bytes.count else { continue }
            for start in 0...(bytes.count - fingerprint.byteCount) {
                let end = start + fingerprint.byteCount
                if Data(SHA256.hash(data: bytes[start..<end])) == fingerprint.digest {
                    return true
                }
            }
        }
        return false
    }

    private func encodedVariants(for secretData: Data, secretString: String) -> [String] {
        var variants = Set<String>()

        let base64 = secretData.base64EncodedString()
        if base64 != secretString {
            variants.insert(base64)
        }

        if let percentEncoded = secretString.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
           percentEncoded != secretString {
            variants.insert(percentEncoded)
        }

        let hexEncoded = secretData.map { String(format: "%02x", $0) }.joined()
        if hexEncoded != secretString {
            variants.insert(hexEncoded)
        }
        let uppercaseHexEncoded = hexEncoded.uppercased()
        if uppercaseHexEncoded != secretString {
            variants.insert(uppercaseHexEncoded)
        }

        return Array(variants)
    }

    private static func containsBinaryControlCharacters(_ output: String) -> Bool {
        output.unicodeScalars.contains { scalar in
            switch scalar.value {
            case 0x09, 0x0A, 0x0D:
                return false
            case 0x00..<0x20, 0x7F:
                return true
            default:
                return false
            }
        }
    }
}
