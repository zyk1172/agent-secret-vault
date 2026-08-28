import Darwin
import Dispatch
import Foundation
import Security

public enum AppControlIPCControllerError: Error, Equatable, Sendable {
    case notStarted
    case invalidMaxActiveClients
}

/// The App-control socket has its own token and an additional peer identity
/// check.  The injectable closure is used by tests; production uses the
/// peer PID and macOS code-signing identity rather than the shared MCP token.
public struct AppControlPeerAuthenticator: @unchecked Sendable {
    public static let svltBundleIdentifier = "com.agent-secret-vault.SVLT"
    /// The Team ID is part of the designated requirement. Checking only the
    /// bundle identifier would allow another developer-signed binary with the
    /// same identifier to connect to the privileged App-control socket.
    public static let svltTeamIdentifier = "9KXSB4HR69"
    public static let svltDesignatedRequirement =
        #"identifier "com.agent-secret-vault.SVLT" and anchor apple generic and certificate leaf[subject.OU] = "9KXSB4HR69""#

    private let validator: @Sendable (Int32) -> Bool

    public init(validator: @escaping @Sendable (Int32) -> Bool) {
        self.validator = validator
    }

    public static func production() -> Self {
        Self { fileDescriptor in
            guard Self.isOwner(fileDescriptor) else { return false }
            return Self.isSignedSVLTApp(fileDescriptor)
        }
    }

    public func isAuthorized(fileDescriptor: Int32) -> Bool {
        validator(fileDescriptor)
    }

    private static func isOwner(_ fileDescriptor: Int32) -> Bool {
        var uid = uid_t()
        var gid = gid_t()
        guard getpeereid(fileDescriptor, &uid, &gid) == 0 else { return false }
        return uid == geteuid()
    }

    private static func isSignedSVLTApp(_ fileDescriptor: Int32) -> Bool {
        var pid = pid_t()
        var pidLength = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(
            fileDescriptor,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &pid,
            &pidLength
        ) == 0, pid > 0 else {
            return false
        }

        // LOCAL_PEERTOKEN is the kernel-provided audit token for the peer.
        // Requiring it to resolve to the same PID prevents a stale or
        // user-supplied PID from being treated as the App identity.
        var auditToken = audit_token_t()
        var auditTokenLength = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(
            fileDescriptor,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &auditToken,
            &auditTokenLength
        ) == 0,
        // audit_token_t is the Darwin eight-word token; word 5 is the
        // process ID in the public macOS layout.
        pid_t(auditToken.val.5) == pid
        else {
            return false
        }

        var guestCode: SecCode?
        let attributes: [CFString: Any] = [kSecGuestAttributePid: pid]
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            SecCSFlags(),
            &guestCode
        ) == errSecSuccess,
        let guestCode
        else {
            return false
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode
        else {
            return false
        }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            svltDesignatedRequirement as CFString,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess,
        let requirement,
        SecStaticCodeCheckValidity(staticCode, SecCSFlags(), requirement) == errSecSuccess
        else {
            return false
        }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(),
            &information
        ) == errSecSuccess,
        let information = information as? [String: Any]
        else {
            return false
        }

        return (information[kSecCodeInfoIdentifier as String] as? String)
            == svltBundleIdentifier
    }
}

public final class AppControlIPCController: @unchecked Sendable {
    private let server: UnixSocketServer
    private let handler: AppControlRequestHandler
    private let peerAuthenticator: AppControlPeerAuthenticator
    private let maxActiveClients: Int
    private let stateLock = NSLock()
    private let clientGroup = DispatchGroup()
    private var boundSocket: BoundUnixSocket?
    private var acceptTask: Task<Void, Never>?
    private var isStopping = false
    private var authenticator: AppControlTokenAuthenticator?
    private var activeClientFDs: Set<Int32> = []

    public init(
        server: UnixSocketServer,
        handler: AppControlRequestHandler,
        peerAuthenticator: AppControlPeerAuthenticator = .production(),
        maxActiveClients: Int = 8
    ) {
        self.server = server
        self.handler = handler
        self.peerAuthenticator = peerAuthenticator
        self.maxActiveClients = maxActiveClients
    }

    deinit { stop() }

    public var endpointMetadata: AppIPCController.EndpointMetadata {
        AppIPCController.EndpointMetadata(socketPath: server.configuration.socketURL.path)
    }

    public func start() throws {
        guard maxActiveClients > 0 else {
            throw AppControlIPCControllerError.invalidMaxActiveClients
        }
        stateLock.lock()
        if boundSocket != nil || isStopping {
            stateLock.unlock()
            return
        }

        let token = CapabilityToken.random()
        do {
            try server.writeCapabilityToken(token)
            let socket = try server.bindListeningSocket()
            let authenticator = AppControlTokenAuthenticator(expectedToken: token)
            let task = Task.detached(priority: .userInitiated) { [weak self, socket, authenticator] in
                guard let self else { return }
                await self.acceptLoop(socket: socket, authenticator: authenticator)
            }
            boundSocket = socket
            self.authenticator = authenticator
            acceptTask = task
            stateLock.unlock()
        } catch {
            stateLock.unlock()
            throw error
        }
    }

    public func stop() {
        stateLock.lock()
        guard !isStopping else {
            stateLock.unlock()
            return
        }
        guard boundSocket != nil || acceptTask != nil else {
            stateLock.unlock()
            return
        }
        isStopping = true
        let task = acceptTask
        let socket = boundSocket
        let clients = Array(activeClientFDs)
        acceptTask = nil
        boundSocket = nil
        authenticator = nil
        stateLock.unlock()

        task?.cancel()
        socket?.close()
        for client in clients { _ = Darwin.shutdown(client, SHUT_RDWR) }
        clientGroup.wait()
        stateLock.lock()
        isStopping = false
        stateLock.unlock()
    }

    public func handleAuthenticatedFrame(_ frame: Data) async throws -> Data {
        let authenticator = stateLock.withLock { self.authenticator }
        guard let authenticator else {
            throw AppControlIPCControllerError.notStarted
        }
        return try await handleAuthenticatedFrame(frame, authenticator: authenticator)
    }

    private func acceptLoop(
        socket: BoundUnixSocket,
        authenticator: AppControlTokenAuthenticator
    ) async {
        while !Task.isCancelled {
            let clientFD = Darwin.accept(socket.fileDescriptor, nil, nil)
            if clientFD < 0 {
                if errno == EINTR { continue }
                if Task.isCancelled || socket.fileDescriptor < 0 { return }
                continue
            }
            guard Self.configureAcceptedSocket(clientFD),
                  peerAuthenticator.isAuthorized(fileDescriptor: clientFD),
                  registerClientIfAvailable(fileDescriptor: clientFD)
            else {
                _ = Darwin.shutdown(clientFD, SHUT_RDWR)
                Darwin.close(clientFD)
                continue
            }
            Task.detached(priority: .userInitiated) { [weak self, authenticator] in
                await self?.handleClient(fileDescriptor: clientFD, authenticator: authenticator)
            }
        }
    }

    private func handleClient(
        fileDescriptor: Int32,
        authenticator: AppControlTokenAuthenticator
    ) async {
        defer {
            unregisterClient(fileDescriptor: fileDescriptor)
            Darwin.close(fileDescriptor)
            clientGroup.leave()
        }
        do {
            try setIOTimeouts(on: fileDescriptor)
            let frame = try readFrame(from: fileDescriptor)
            let response = try await handleAuthenticatedFrame(frame, authenticator: authenticator)
            try writeAll(response, to: fileDescriptor)
        } catch {
            let frame = try? IPCFrameCodec.encode(AppControlResponse.failure(code: "APP_CONTROL_REQUEST_FAILED"))
            if let frame { try? writeAll(frame, to: fileDescriptor) }
        }
    }

    private func handleAuthenticatedFrame(
        _ frame: Data,
        authenticator: AppControlTokenAuthenticator
    ) async throws -> Data {
        do {
            let authenticated = try IPCFrameCodec.decode(
                AuthenticatedAppControlRequest.self,
                from: frame
            )
            guard authenticator.authenticate(authenticated) else {
                return try IPCFrameCodec.encode(AppControlResponse.failure(code: "INVALID_APP_CONTROL_TOKEN"))
            }
            return try IPCFrameCodec.encode(await handler.handle(authenticated.request))
        } catch let error as IPCFrameError {
            return try IPCFrameCodec.encode(AppControlResponse.failure(code: error.responseCode))
        } catch {
            return try IPCFrameCodec.encode(AppControlResponse.failure(code: "APP_CONTROL_REQUEST_FAILED"))
        }
    }

    private func registerClientIfAvailable(fileDescriptor: Int32) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard boundSocket != nil, activeClientFDs.count < maxActiveClients else { return false }
        activeClientFDs.insert(fileDescriptor)
        clientGroup.enter()
        return true
    }

    private func unregisterClient(fileDescriptor: Int32) {
        stateLock.lock()
        activeClientFDs.remove(fileDescriptor)
        stateLock.unlock()
    }

    private static func configureAcceptedSocket(_ fileDescriptor: Int32) -> Bool {
        var enabled: Int32 = 1
        return withUnsafePointer(to: &enabled) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                pointer,
                socklen_t(MemoryLayout<Int32>.size)
            ) == 0
        }
    }

    private func setIOTimeouts(on fileDescriptor: Int32) throws {
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        let receive = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        let send = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        guard receive == 0, send == 0 else {
            throw IPCSocketError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func readFrame(from fileDescriptor: Int32) throws -> Data {
        var header = Data(count: 4)
        try readExactly(&header, from: fileDescriptor)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= IPCFrameCodec.maxFrameBytes else { throw IPCFrameError.frameTooLarge }
        var payload = Data(count: Int(length))
        try readExactly(&payload, from: fileDescriptor)
        return header + payload
    }

    private func readExactly(_ data: inout Data, from fileDescriptor: Int32) throws {
        var offset = 0
        let byteCount = data.count
        while offset < byteCount {
            let count = data.withUnsafeMutableBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.read(fileDescriptor, baseAddress.advanced(by: offset), byteCount - offset)
            }
            if count > 0 { offset += count; continue }
            if count < 0, errno == EINTR { continue }
            throw IPCFrameError.incompleteFrame
        }
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.write(fileDescriptor, baseAddress.advanced(by: offset), data.count - offset)
            }
            if count > 0 { offset += count; continue }
            if count < 0, errno == EINTR { continue }
            throw IPCSocketError.operationFailed("write", errno: errno)
        }
    }
}

private struct AppControlTokenAuthenticator: Sendable {
    let expectedToken: CapabilityToken

    func authenticate(_ request: AuthenticatedAppControlRequest) -> Bool {
        expectedToken.constantTimeEquals(request.capabilityToken)
    }
}

private extension IPCFrameError {
    var responseCode: String {
        switch self {
        case .frameTooLarge: return "FRAME_TOO_LARGE"
        case .incompleteFrame, .lengthMismatch: return "INVALID_FRAME"
        }
    }
}
