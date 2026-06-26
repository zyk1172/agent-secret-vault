import Foundation
import VaultAuthorization
import VaultCore

public enum TemplateValidationError: Error, Equatable, Sendable {
    case templateMismatch
    case undeclaredExecutable
    case undeclaredParameter(String)
    case missingParameter(String)
    case secretInNonSecretField(String)
    case destinationNotAllowed
    case riskEscalation
    case shellMetacharacters(String)
    case relativeExecutablePath
}

public struct ValidatedExecution: Equatable, Sendable {
    public let templateID: String
    public let executable: String
    public let arguments: [ValidatedArgument]
    public let risk: RiskClass
    public let destinationHost: String?
    public let destinationPath: String?

    public init(
        templateID: String,
        executable: String,
        arguments: [ValidatedArgument],
        risk: RiskClass,
        destinationHost: String?,
        destinationPath: String?
    ) {
        self.templateID = templateID
        self.executable = executable
        self.arguments = arguments
        self.risk = risk
        self.destinationHost = destinationHost
        self.destinationPath = destinationPath
    }
}

public enum ValidatedArgument: Equatable, Sendable {
    case literal(String)
    case value(name: String, value: String)
    case secret(name: String, reference: SecretReference)
}

public struct TemplateValidator: Sendable {
    public init() {}

    public func validate(
        _ request: ExecutionRequest,
        against template: ExecutionTemplate
    ) throws -> ValidatedExecution {
        guard request.templateID == template.id else {
            throw TemplateValidationError.templateMismatch
        }

        try validateExecutable(template.executable)

        guard request.executable == template.executable else {
            throw TemplateValidationError.undeclaredExecutable
        }

        guard request.requestedRisk.rawValue <= template.risk.rawValue else {
            throw TemplateValidationError.riskEscalation
        }

        try validateDestination(request, against: template)

        let declaredValues = Set(template.arguments.compactMap(\.valueName))
        let declaredSecrets = Set(template.arguments.compactMap(\.secretName))

        let extraValueNames = Set(request.values.keys).subtracting(declaredValues)
        if let extra = extraValueNames.sorted().first {
            throw TemplateValidationError.undeclaredParameter(extra)
        }

        let extraSecretNames = Set(request.secrets.keys).subtracting(declaredSecrets)
        if let extra = extraSecretNames.sorted().first {
            throw TemplateValidationError.undeclaredParameter(extra)
        }

        let arguments = try template.arguments.map { slot in
            try validateArgument(slot, values: request.values, secrets: request.secrets)
        }

        return ValidatedExecution(
            templateID: template.id,
            executable: template.executable,
            arguments: arguments,
            risk: template.risk,
            destinationHost: request.destinationHost,
            destinationPath: request.destinationPath
        )
    }

    private func validateExecutable(_ executable: String) throws {
        guard executable.hasPrefix("/") else {
            throw TemplateValidationError.relativeExecutablePath
        }

        if Self.containsShellMetacharacters(executable) {
            throw TemplateValidationError.shellMetacharacters("executable")
        }
    }

    private func validateDestination(
        _ request: ExecutionRequest,
        against template: ExecutionTemplate
    ) throws {
        if let destinationHost = request.destinationHost,
           !template.allowedHosts.contains(destinationHost) {
            throw TemplateValidationError.destinationNotAllowed
        }

        if let destinationPath = request.destinationPath,
           !template.allowedPaths.contains(destinationPath) {
            throw TemplateValidationError.destinationNotAllowed
        }
    }

    private func validateArgument(
        _ slot: ArgumentSlot,
        values: [String: String],
        secrets: [String: SecretReference]
    ) throws -> ValidatedArgument {
        switch slot {
        case let .literal(value):
            if Self.containsShellMetacharacters(value) {
                throw TemplateValidationError.shellMetacharacters("literal")
            }
            return .literal(value)
        case let .value(name):
            guard let value = values[name] else {
                throw TemplateValidationError.missingParameter(name)
            }

            if value.hasPrefix("secret://") {
                throw TemplateValidationError.secretInNonSecretField(name)
            }

            if Self.containsShellMetacharacters(value) {
                throw TemplateValidationError.shellMetacharacters(name)
            }

            return .value(name: name, value: value)
        case let .secret(name):
            guard let reference = secrets[name] else {
                throw TemplateValidationError.missingParameter(name)
            }

            return .secret(name: name, reference: reference)
        }
    }

    private static func containsShellMetacharacters(_ value: String) -> Bool {
        let disallowedFragments = [";", "&&", "|", "`", "$(", ">", "<", "\n", "\r"]
        return disallowedFragments.contains { value.contains($0) }
    }
}

private extension ArgumentSlot {
    var valueName: String? {
        if case let .value(name) = self {
            return name
        }

        return nil
    }

    var secretName: String? {
        if case let .secret(name) = self {
            return name
        }

        return nil
    }
}
