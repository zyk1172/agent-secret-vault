import Darwin
import Foundation

public enum IPCFrameError: Error, Equatable, Sendable {
    case incompleteFrame
    case frameTooLarge
    case lengthMismatch(expected: Int, actual: Int)
}

public enum IPCSocketError: Error, Equatable, Sendable {
    case socketPathTooLong(maxBytes: Int, actualBytes: Int)
    case operationFailed(String, errno: Int32)
}

public enum IPCFrameCodec {
    public static let maxFrameBytes = 1_048_576

    public static func encode<T: Encodable>(_ message: T) throws -> Data {
        let payload = try JSONEncoder().encode(message)
        guard payload.count <= maxFrameBytes else {
            throw IPCFrameError.frameTooLarge
        }

        var frame = Data()
        appendBigEndianUInt32(UInt32(payload.count), to: &frame)
        frame.append(payload)
        return frame
    }

    public static func decode<T: Decodable>(
        _ type: T.Type,
        from frame: Data
    ) throws -> T {
        guard frame.count >= 4 else {
            throw IPCFrameError.incompleteFrame
        }

        let payloadLength = frame.prefix(4).reduce(UInt32(0)) { partial, byte in
            (partial << 8) | UInt32(byte)
        }

        guard payloadLength <= maxFrameBytes else {
            throw IPCFrameError.frameTooLarge
        }

        let actualLength = frame.count - 4
        guard actualLength == Int(payloadLength) else {
            throw IPCFrameError.lengthMismatch(
                expected: Int(payloadLength),
                actual: actualLength
            )
        }

        return try JSONDecoder().decode(T.self, from: frame.dropFirst(4))
    }

    private static func appendBigEndianUInt32(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }
}

public struct UnixSocketServerConfiguration: Equatable, Sendable {
    public let directoryURL: URL
    public let socketURL: URL
    public let tokenURL: URL

    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
        self.socketURL = directoryURL.appending(path: "agent-secret-vault.sock")
        self.tokenURL = directoryURL.appending(path: "capability.token")
    }

    public static func defaultConfiguration(
        fileManager: FileManager = .default
    ) throws -> UnixSocketServerConfiguration {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )

        return UnixSocketServerConfiguration(
            directoryURL: appSupport
                .appending(path: "AgentSecretVault")
                .appending(path: "IPC")
        )
    }
}

public final class UnixSocketServer: @unchecked Sendable {
    public let configuration: UnixSocketServerConfiguration
    private let fileManager: FileManager

    public init(
        configuration: UnixSocketServerConfiguration,
        fileManager: FileManager = .default
    ) {
        self.configuration = configuration
        self.fileManager = fileManager
    }

    public func prepareDirectory() throws {
        try fileManager.createDirectory(
            at: configuration.directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try chmod(configuration.directoryURL.path, 0o700).throwIfFailed()
    }

    public func writeCapabilityToken(_ token: CapabilityToken) throws {
        try prepareDirectory()
        let temporaryURL = configuration.directoryURL.appendingPathComponent(
            ".capability.\(UUID().uuidString).tmp"
        )
        do {
            try Data(token.rawValue.utf8).write(to: temporaryURL, options: [.atomic])
            try chmod(temporaryURL.path, 0o600).throwIfFailed()
            guard rename(temporaryURL.path, configuration.tokenURL.path) == 0 else {
                throw IPCSocketError.operationFailed("rename-token", errno: errno)
            }
            try chmod(configuration.tokenURL.path, 0o600).throwIfFailed()
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }

    public func bindListeningSocket(backlog: Int32 = 16) throws -> BoundUnixSocket {
        try prepareDirectory()

        let fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fileDescriptor >= 0 else {
            throw IPCSocketError.operationFailed("socket", errno: errno)
        }

        do {
            try setNoSIGPIPE(fileDescriptor)
            try unlinkSocketIfPresent()
            var address = try sockaddrUnix(for: configuration.socketURL.path)

            let bindResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                    bind(fileDescriptor, rebound, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bindResult == 0 else {
                throw IPCSocketError.operationFailed("bind", errno: errno)
            }

            try chmod(configuration.socketURL.path, 0o600).throwIfFailed()
            guard listen(fileDescriptor, backlog) == 0 else {
                throw IPCSocketError.operationFailed("listen", errno: errno)
            }

            return BoundUnixSocket(
                fileDescriptor: fileDescriptor,
                socketURL: configuration.socketURL
            )
        } catch {
            Darwin.close(fileDescriptor)
            unlink(configuration.socketURL.path)
            throw error
        }
    }

    private func unlinkSocketIfPresent() throws {
        guard fileManager.fileExists(atPath: configuration.socketURL.path) else {
            return
        }
        guard unlink(configuration.socketURL.path) == 0 else {
            throw IPCSocketError.operationFailed("unlink", errno: errno)
        }
    }

    private func sockaddrUnix(for path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        let pathBytes = Array(path.utf8)
        let maximumPathBytes = MemoryLayout.size(ofValue: address.sun_path) - 1
        guard pathBytes.count <= maximumPathBytes else {
            throw IPCSocketError.socketPathTooLong(
                maxBytes: maximumPathBytes,
                actualBytes: pathBytes.count
            )
        }

        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            rawBuffer.copyBytes(from: pathBytes)
            rawBuffer[pathBytes.count] = 0
        }

        return address
    }

    private func setNoSIGPIPE(_ fileDescriptor: Int32) throws {
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
            throw IPCSocketError.operationFailed("setsockopt", errno: errno)
        }
    }
}

public final class BoundUnixSocket: @unchecked Sendable {
    public let socketURL: URL
    private let stateLock = NSLock()
    private var storedFileDescriptor: Int32

    init(fileDescriptor: Int32, socketURL: URL) {
        self.storedFileDescriptor = fileDescriptor
        self.socketURL = socketURL
    }

    deinit {
        close()
    }

    public var fileDescriptor: Int32 {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }
        return storedFileDescriptor
    }

    public func close() {
        stateLock.lock()
        guard storedFileDescriptor >= 0 else {
            stateLock.unlock()
            return
        }
        let fileDescriptor = storedFileDescriptor
        storedFileDescriptor = -1
        stateLock.unlock()

        _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
        Darwin.close(fileDescriptor)
        unlink(socketURL.path)
    }
}

private extension Int32 {
    func throwIfFailed() throws {
        guard self == 0 else {
            throw IPCSocketError.operationFailed("posix", errno: errno)
        }
    }
}
