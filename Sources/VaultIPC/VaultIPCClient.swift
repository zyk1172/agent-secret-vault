import Darwin
import Foundation
import VaultCore

public enum VaultIPCClientError: Error, Equatable, Sendable {
    case endpointUnavailable
    case endpointOwnershipInvalid
    case endpointPermissionsInvalid
    case responseFailure(String)
    case unexpectedResponse
    case operationFailed(String, errno: Int32)
    case frameTooLarge
    case incompleteFrame
}

/// Short-lived, one-request-per-connection client used by the GUI and other
/// trusted local integrations. It rereads the token for every connection so a
/// restarted Agent invalidates all previous capabilities.
public actor VaultIPCClient {
    private let configuration: UnixSocketServerConfiguration

    public init(configuration: UnixSocketServerConfiguration) {
        self.configuration = configuration
    }

    public static func defaultClient() throws -> VaultIPCClient {
        VaultIPCClient(configuration: try .defaultConfiguration())
    }

    public func status() async throws -> Bool {
        let response = try await send(.status)
        guard case let .status(locked) = response else {
            throw unexpected(response)
        }
        return locked
    }

    public func workbenchStatus() async throws -> WorkbenchStatus {
        let response = try await send(.workbenchStatus)
        guard case let .workbenchStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func savedSecretReferences() async throws -> [SecretReferenceMetadata] {
        let response = try await send(.savedReferences)
        guard case let .savedReferences(references) = response else {
            throw unexpected(response)
        }
        return references
    }

    public func pendingRevealSessionIDs() async throws -> [String] {
        let response = try await send(.pendingRevealSessions)
        guard case let .revealSessionIDs(sessionIDs) = response else {
            throw unexpected(response)
        }
        return sessionIDs
    }

    public func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy
    ) async throws -> String {
        let response = try await send(.encryptText(plaintext: plaintext, label: label, policy: policy))
        guard case let .created(reference) = response else {
            throw unexpected(response)
        }
        return reference
    }

    public func deleteRecord(_ reference: String) async throws {
        let response = try await send(.deleteRecord(reference: reference))
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func authorizeHighRisk(reason: String) async throws {
        let response = try await send(.authorizeHighRisk(reason: reason))
        guard case .authorizationApproved = response else {
            throw unexpected(response)
        }
    }

    public func lock() async throws {
        let response = try await send(.lock)
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func clearRevealSessions() async throws {
        let response = try await send(.clearRevealSessions)
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func revealSessionData(sessionID: String) async throws -> RestoredParagraph {
        let response = try await send(.revealSessionData(sessionID: sessionID))
        guard case let .revealSessionData(paragraph) = response else {
            throw unexpected(response)
        }
        return paragraph
    }

    public func restoreReferences(
        references: [String],
        context: RevealContext
    ) async throws -> RestoredParagraph {
        let response = try await send(.restoreReferences(references: references, context: context))
        guard case let .restoredText(text) = response else {
            throw unexpected(response)
        }
        // The Agent deliberately returns text only to this explicit trusted
        // GUI operation. MCP reveal requests use revealSessionOpened instead.
        return RestoredParagraph(text: text, values: [])
    }

    public func send(_ request: IPCRequest) async throws -> IPCResponse {
        try validateEndpoint()
        let token = try readCapabilityToken()
        let fileDescriptor = try connect()
        defer {
            _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
            Darwin.close(fileDescriptor)
        }

        try setIOTimeouts(on: fileDescriptor)
        let frame = try IPCFrameCodec.encode(
            AuthenticatedIPCRequest(capabilityToken: token, request: request)
        )
        try writeAll(frame, to: fileDescriptor)
        let responseFrame = try readFrame(from: fileDescriptor)
        let response = try IPCFrameCodec.decode(IPCResponse.self, from: responseFrame)
        if case let .failure(code) = response {
            throw VaultIPCClientError.responseFailure(code)
        }
        return response
    }

    private func validateEndpoint() throws {
        var directoryStat = stat()
        guard lstat(configuration.directoryURL.path, &directoryStat) == 0,
              (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == geteuid(),
              (directoryStat.st_mode & 0o777) == 0o700
        else {
            throw VaultIPCClientError.endpointOwnershipInvalid
        }

        var socketStat = stat()
        guard lstat(configuration.socketURL.path, &socketStat) == 0,
              (socketStat.st_mode & S_IFMT) == S_IFSOCK,
              socketStat.st_uid == geteuid()
        else {
            throw VaultIPCClientError.endpointUnavailable
        }
        guard (socketStat.st_mode & 0o777) == 0o600 else {
            throw VaultIPCClientError.endpointPermissionsInvalid
        }

        var tokenStat = stat()
        guard lstat(configuration.tokenURL.path, &tokenStat) == 0,
              (tokenStat.st_mode & S_IFMT) == S_IFREG,
              tokenStat.st_uid == geteuid()
        else {
            throw VaultIPCClientError.endpointOwnershipInvalid
        }
        guard (tokenStat.st_mode & 0o777) == 0o600 else {
            throw VaultIPCClientError.endpointPermissionsInvalid
        }
    }

    private func readCapabilityToken() throws -> CapabilityToken {
        let data = try Data(contentsOf: configuration.tokenURL)
        let rawValue = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return try CapabilityToken(base64Encoded: rawValue)
    }

    private func connect() throws -> Int32 {
        let fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fileDescriptor >= 0 else {
            throw VaultIPCClientError.operationFailed("socket", errno: errno)
        }
        do {
            try setNoSIGPIPE(on: fileDescriptor)
            var address = try sockaddrUnix(for: configuration.socketURL.path)
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                    Darwin.connect(
                        fileDescriptor,
                        rebound,
                        socklen_t(MemoryLayout<sockaddr_un>.size)
                    )
                }
            }
            guard result == 0 else {
                throw VaultIPCClientError.operationFailed("connect", errno: errno)
            }
            return fileDescriptor
        } catch {
            Darwin.close(fileDescriptor)
            throw error
        }
    }

    private func sockaddrUnix(for path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        let pathBytes = Array(path.utf8)
        let maximumPathBytes = MemoryLayout.size(ofValue: address.sun_path) - 1
        guard pathBytes.count <= maximumPathBytes else {
            throw VaultIPCClientError.operationFailed("socket-path", errno: ENAMETOOLONG)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }
        return address
    }

    private func setNoSIGPIPE(on fileDescriptor: Int32) throws {
        var enabled: Int32 = 1
        let result = withUnsafePointer(to: &enabled) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                pointer,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        guard result == 0 else {
            throw VaultIPCClientError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func setIOTimeouts(on fileDescriptor: Int32) throws {
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        let receiveResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        let sendResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        guard receiveResult == 0, sendResult == 0 else {
            throw VaultIPCClientError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func readFrame(from fileDescriptor: Int32) throws -> Data {
        let header = try readExactly(4, from: fileDescriptor)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= IPCFrameCodec.maxFrameBytes else {
            throw VaultIPCClientError.frameTooLarge
        }
        return header + (try readExactly(Int(length), from: fileDescriptor))
    }

    private func readExactly(_ byteCount: Int, from fileDescriptor: Int32) throws -> Data {
        var data = Data(count: byteCount)
        var offset = 0
        while offset < byteCount {
            let count = data.withUnsafeMutableBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.read(fileDescriptor, baseAddress.advanced(by: offset), byteCount - offset)
            }
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                throw VaultIPCClientError.incompleteFrame
            } else {
                throw VaultIPCClientError.incompleteFrame
            }
        }
        return data
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.write(fileDescriptor, baseAddress.advanced(by: offset), data.count - offset)
            }
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                throw VaultIPCClientError.operationFailed("write", errno: errno)
            }
        }
    }

    private func unexpected(_ response: IPCResponse) -> VaultIPCClientError {
        if case let .failure(code) = response {
            return .responseFailure(code)
        }
        return .unexpectedResponse
    }
}
