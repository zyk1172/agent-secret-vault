import Foundation

public enum OutputQuarantineReason: Equatable, Sendable {
    case binaryOutput
    case invalidUTF8
    case emptySecretMaterial
    case encodedSecretVariantDetected
}

public enum SanitizedProcessResult: Equatable, Sendable {
    case sanitized(ProcessResult)
    case quarantined(reason: OutputQuarantineReason)
}

public struct OutputSanitizer: Sendable {
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
            encodedVariants(for: secretData, secretString: secretString).contains {
                output.contains($0)
            }
        }
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
