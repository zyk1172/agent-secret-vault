import Darwin
import Foundation
import VaultIPC

public enum AppIPCControllerError: Error, Equatable, Sendable {
    case notStarted
}

public final class AppIPCController: @unchecked Sendable {
    public struct EndpointMetadata: Codable, Equatable, Sendable {
        public let socketPath: String
    }

    private let server: UnixSocketServer
    private let handler: IPCRequestHandler
    private let stateLock = NSLock()
    private var boundSocket: BoundUnixSocket?
    private var acceptTask: Task<Void, Never>?
    private var authenticator: IPCAuthenticator?

    public init(server: UnixSocketServer, handler: IPCRequestHandler) {
        self.server = server
        self.handler = handler
    }

    deinit {
        stop()
    }

    public var endpointMetadata: EndpointMetadata {
        EndpointMetadata(socketPath: server.configuration.socketURL.path)
    }

    public func start() throws {
        stateLock.lock()
        if boundSocket != nil {
            stateLock.unlock()
            return
        }
        stateLock.unlock()

        let token = CapabilityToken.random()
        try server.writeCapabilityToken(token)
        let socket = try server.bindListeningSocket()
        let authenticator = IPCAuthenticator(expectedToken: token)

        let task = Task.detached(priority: .userInitiated) { [weak self, socket, authenticator] in
            guard let self else {
                return
            }
            await self.acceptLoop(socket: socket, authenticator: authenticator)
        }

        stateLock.lock()
        self.boundSocket = socket
        self.authenticator = authenticator
        self.acceptTask = task
        stateLock.unlock()
    }

    public func stop() {
        stateLock.lock()
        let task = acceptTask
        let socket = boundSocket
        acceptTask = nil
        boundSocket = nil
        authenticator = nil
        stateLock.unlock()

        task?.cancel()
        socket?.close()
    }

    public func handleAuthenticatedFrame(_ frame: Data) async throws -> Data {
        guard let authenticator = currentAuthenticator() else {
            throw AppIPCControllerError.notStarted
        }
        return try await handleAuthenticatedFrame(frame, authenticator: authenticator)
    }

    private func currentAuthenticator() -> IPCAuthenticator? {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }
        return authenticator
    }

    private func acceptLoop(socket: BoundUnixSocket, authenticator: IPCAuthenticator) async {
        while !Task.isCancelled {
            let clientFD = accept(socket.fileDescriptor, nil, nil)
            if clientFD < 0 {
                if Task.isCancelled || socket.fileDescriptor < 0 {
                    return
                }
                continue
            }

            Task.detached(priority: .userInitiated) { [weak self, authenticator] in
                await self?.handleClient(fileDescriptor: clientFD, authenticator: authenticator)
            }
        }
    }

    private func handleClient(fileDescriptor: Int32, authenticator: IPCAuthenticator) async {
        defer {
            Darwin.close(fileDescriptor)
        }

        do {
            let frame = try readFrame(from: fileDescriptor)
            let responseFrame = try await handleAuthenticatedFrame(frame, authenticator: authenticator)
            try writeAll(responseFrame, to: fileDescriptor)
        } catch {
            let failureFrame = try? IPCFrameCodec.encode(IPCResponse.failure(code: "IPC_REQUEST_FAILED"))
            if let failureFrame {
                try? writeAll(failureFrame, to: fileDescriptor)
            }
        }
    }

    private func handleAuthenticatedFrame(
        _ frame: Data,
        authenticator: IPCAuthenticator
    ) async throws -> Data {
        do {
            let authenticated = try IPCFrameCodec.decode(AuthenticatedIPCRequest.self, from: frame)
            let request = try authenticator.authenticate(authenticated)
            let response = try await handler.handle(request)
            return try IPCFrameCodec.encode(response)
        } catch IPCAuthenticationError.invalidCapabilityToken {
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "INVALID_CAPABILITY_TOKEN"))
        } catch IPCRequestHandlerError.unsupportedRequest {
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "UNSUPPORTED_REQUEST"))
        } catch {
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "REQUEST_FAILED"))
        }
    }

    private func readFrame(from fileDescriptor: Int32) throws -> Data {
        let header = try readExactly(byteCount: 4, from: fileDescriptor)
        let payloadLength = header.reduce(UInt32(0)) { partial, byte in
            (partial << 8) | UInt32(byte)
        }
        guard payloadLength <= IPCFrameCodec.maxFrameBytes else {
            throw IPCFrameError.frameTooLarge
        }
        let payload = try readExactly(byteCount: Int(payloadLength), from: fileDescriptor)
        return header + payload
    }

    private func readExactly(byteCount: Int, from fileDescriptor: Int32) throws -> Data {
        var data = Data(count: byteCount)
        var offset = 0

        while offset < byteCount {
            let readCount = data.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    fileDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    byteCount - offset
                )
            }
            guard readCount > 0 else {
                throw IPCFrameError.incompleteFrame
            }
            offset += readCount
        }

        return data
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer in
                Darwin.write(
                    fileDescriptor,
                    buffer.baseAddress!.advanced(by: offset),
                    data.count - offset
                )
            }
            guard written > 0 else {
                throw IPCSocketError.operationFailed("write", errno: errno)
            }
            offset += written
        }
    }
}
