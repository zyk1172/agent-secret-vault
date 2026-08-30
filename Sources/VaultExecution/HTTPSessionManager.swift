import Dispatch
import Foundation

public enum HTTPSessionManagerError: Error, Equatable, Sendable {
    case sessionNotFound
    case sessionExpired
    case scopeMismatch
    case sessionLimitReached
    case redirectRequiresReview
    case responseTooLarge
}

/// Scope for a reusable HTTP transport. It describes the connection and
/// authentication identity, not the operation authorization that permits a
/// request. The path and HTTP method are deliberately absent so an existing
/// connection can serve multiple policy-reviewed requests.
public struct HTTPSessionScope: Hashable, Sendable {
    public let principal: String
    public let scheme: String
    public let host: String
    public let port: Int
    public let authenticationProfile: String
    public let secretReferenceIDs: [String]
    public let securityGeneration: UInt64

    public init(
        principal: String,
        scheme: String,
        host: String,
        port: Int,
        authenticationProfile: String,
        secretReferenceIDs: [String],
        securityGeneration: UInt64
    ) {
        self.principal = principal
        self.scheme = scheme.lowercased()
        self.host = host.lowercased()
        self.port = port
        self.authenticationProfile = authenticationProfile
        // The policy boundary rejects duplicate references. Do not silently
        // turn malformed input into a different transport scope here.
        self.secretReferenceIDs = secretReferenceIDs.sorted()
        self.securityGeneration = securityGeneration
    }
}

public struct HTTPTransportResponse: Sendable {
    public let data: Data
    public let statusCode: Int
    public let contentType: String?
    public let sessionID: String

    public init(data: Data, statusCode: Int, contentType: String?, sessionID: String) {
        self.data = data
        self.statusCode = statusCode
        self.contentType = contentType
        self.sessionID = sessionID
    }
}

/// Owns short-lived, in-memory URLSession connections. It never persists
/// cookies or credentials and it refuses every redirect. The session ID is an
/// opaque transport handle; scope and policy are checked by the caller for
/// every request.
public actor HTTPSessionManager {
    private struct Record {
        let id: String
        let scope: HTTPSessionScope
        let session: URLSession
        let createdTick: UInt64
        var lastUsedTick: UInt64
    }

    private let idleTTL: Duration
    private let absoluteTTL: Duration
    private let idleNanoseconds: UInt64
    private let absoluteNanoseconds: UInt64
    private let maxSessionsPerPrincipal: Int
    private let maxGlobalSessions: Int
    private let monotonicNow: @Sendable () -> UInt64
    private let configurationProvider: @Sendable () -> URLSessionConfiguration
    private var records: [String: Record] = [:]

    public init(
        idleTTL: Duration = .seconds(300),
        absoluteTTL: Duration = .seconds(1_800),
        maxSessionsPerPrincipal: Int = 8,
        maxGlobalSessions: Int = 32,
        monotonicNow: @escaping @Sendable () -> UInt64 = HTTPSessionManager.defaultMonotonicNow,
        configurationProvider: @escaping @Sendable () -> URLSessionConfiguration = { URLSessionConfiguration.ephemeral }
    ) {
        self.idleTTL = idleTTL
        self.absoluteTTL = absoluteTTL
        self.idleNanoseconds = Self.nanoseconds(for: idleTTL)
        self.absoluteNanoseconds = Self.nanoseconds(for: absoluteTTL)
        self.maxSessionsPerPrincipal = max(1, maxSessionsPerPrincipal)
        self.maxGlobalSessions = max(1, maxGlobalSessions)
        self.monotonicNow = monotonicNow
        self.configurationProvider = configurationProvider
    }

    public func execute(
        request: URLRequest,
        scope: HTTPSessionScope,
        requestedSessionID: String? = nil,
        maxResponseBytes: Int = 1_048_576
    ) async throws -> HTTPTransportResponse {
        guard maxResponseBytes > 0 else { throw HTTPSessionManagerError.responseTooLarge }
        await reapExpired()
        let record: Record
        if let requestedSessionID {
            guard let requested = records[requestedSessionID] else {
                throw HTTPSessionManagerError.sessionNotFound
            }
            guard requested.scope == scope else {
                throw HTTPSessionManagerError.scopeMismatch
            }
            guard !isExpired(requested) else {
                close(id: requested.id)
                throw HTTPSessionManagerError.sessionExpired
            }
            record = requested
        } else if let existing = records.values.first(where: { $0.scope == scope && !isExpired($0) }) {
            record = existing
        } else {
            record = try createRecord(scope: scope)
        }

        var current = record
        current.lastUsedTick = monotonicNow()
        records[current.id] = current

        // URLSession's session delegate is shared by every task. Use a fresh
        // task delegate/tracker for this request so concurrent redirects cannot
        // reset or consume one another's rejection state.
        let redirectTracker = HTTPRedirectTracker()
        do {
            let (bytes, response) = try await current.session.bytes(
                for: request,
                delegate: HTTPRedirectRejectingDelegate(tracker: redirectTracker)
            )
            guard let httpResponse = response as? HTTPURLResponse else {
                throw SecretOperationExecutionError.processFailed
            }
            guard !(300...399).contains(httpResponse.statusCode) else {
                throw HTTPSessionManagerError.redirectRequiresReview
            }
            var data = Data()
            data.reserveCapacity(min(maxResponseBytes, 64 * 1024))
            for try await byte in bytes {
                guard data.count < maxResponseBytes else {
                    throw HTTPSessionManagerError.responseTooLarge
                }
                data.append(byte)
            }
            return HTTPTransportResponse(
                data: data,
                statusCode: httpResponse.statusCode,
                contentType: httpResponse.value(forHTTPHeaderField: "Content-Type"),
                sessionID: current.id
            )
        } catch let error as HTTPSessionManagerError {
            throw error
        } catch {
            if redirectTracker.didRejectRedirect {
                throw HTTPSessionManagerError.redirectRequiresReview
            }
            throw error
        }
    }

    public func invalidateAll() {
        let sessions = records.values.map(\.session)
        records.removeAll()
        sessions.forEach { $0.invalidateAndCancel() }
    }

    public func activeSessionCount(for principal: String? = nil) async -> Int {
        await reapExpired()
        guard let principal else { return records.count }
        return records.values.filter { $0.scope.principal == principal }.count
    }

    private func createRecord(scope: HTTPSessionScope) throws -> Record {
        let globalCount = records.count
        let principalCount = records.values.filter { $0.scope.principal == scope.principal }.count
        guard globalCount < maxGlobalSessions, principalCount < maxSessionsPerPrincipal else {
            throw HTTPSessionManagerError.sessionLimitReached
        }

        let configuration = configurationProvider()
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(
            configuration: configuration,
            delegate: nil,
            delegateQueue: nil
        )
        let id = "http_session_\(UUID().uuidString.lowercased())"
        let tick = monotonicNow()
        let record = Record(
            id: id,
            scope: scope,
            session: session,
            createdTick: tick,
            lastUsedTick: tick
        )
        records[id] = record
        return record
    }

    private func reapExpired() async {
        let expired = records.values.filter(isExpired).map(\.id)
        for id in expired {
            close(id: id)
        }
    }

    private func close(id: String) {
        guard let record = records.removeValue(forKey: id) else { return }
        record.session.invalidateAndCancel()
    }

    private func isExpired(_ record: Record) -> Bool {
        let now = monotonicNow()
        return Self.deadlineReached(now, start: record.lastUsedTick, duration: idleNanoseconds)
            || Self.deadlineReached(now, start: record.createdTick, duration: absoluteNanoseconds)
    }

    private static func deadlineReached(_ now: UInt64, start: UInt64, duration: UInt64) -> Bool {
        guard duration > 0 else { return true }
        guard start <= UInt64.max - duration else { return false }
        return now >= start + duration
    }

    private static func nanoseconds(for duration: Duration) -> UInt64 {
        let components = duration.components
        guard components.seconds >= 0, components.attoseconds >= 0 else { return 0 }
        let seconds = UInt64(components.seconds)
        let nanos = UInt64(components.attoseconds / 1_000_000_000)
        guard seconds <= UInt64.max / 1_000_000_000 else { return UInt64.max }
        let base = seconds * 1_000_000_000
        return base <= UInt64.max - nanos ? base + nanos : UInt64.max
    }

    public static func defaultMonotonicNow() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }
}

final class HTTPRedirectTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var rejected = false

    var didRejectRedirect: Bool {
        lock.lock()
        defer { lock.unlock() }
        return rejected
    }

    func reset() {
        lock.lock()
        rejected = false
        lock.unlock()
    }

    func markRejected() {
        lock.lock()
        rejected = true
        lock.unlock()
    }
}

private final class HTTPRedirectRejectingDelegate: NSObject, URLSessionTaskDelegate {
    private let tracker: HTTPRedirectTracker

    init(tracker: HTTPRedirectTracker) {
        self.tracker = tracker
    }

    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        tracker.markRejected()
        completionHandler(nil)
    }
}
