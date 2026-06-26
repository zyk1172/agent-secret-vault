import Foundation

public enum RiskClass: Int, Codable, Sendable {
    case read = 0
    case writeOrExternalSend = 1
    case deleteOrCredentialChange = 2
}
