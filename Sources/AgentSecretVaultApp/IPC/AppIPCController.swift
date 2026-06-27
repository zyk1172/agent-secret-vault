import Foundation
import VaultIPC

public final class AppIPCController: Sendable {
    public struct EndpointMetadata: Codable, Equatable, Sendable {
        public let socketPath: String
    }

    private let server: UnixSocketServer
    private let handler: IPCRequestHandler

    public init(server: UnixSocketServer, handler: IPCRequestHandler) {
        self.server = server
        self.handler = handler
    }

    public var endpointMetadata: EndpointMetadata {
        EndpointMetadata(socketPath: server.configuration.socketURL.path)
    }
}
