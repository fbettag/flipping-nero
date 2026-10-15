import Network
import XCTest
@testable import NeroKit

/// Exercises the pivot relay over real localhost sockets: an echo server stands in for
/// the operator's handler, a client stands in for the LAN-side payload.
final class PivotTests: XCTestCase {
    /// Polls `body` until it returns non-nil, with a deadline; keeps NW's async
    /// callback plumbing testable without expectations.
    private func waitFor<T>(_ body: @autoclosure () -> T?, timeout: TimeInterval = 5,
                            what: String) async throws -> T {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let value = body() { return value }
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTFail("timed out waiting for \(what)")
        throw PivotRelay.PivotError.invalidConfig
    }

    func testRelayBridgesBytesBothWays() async throws {
        let echo = EchoServer()
        let echoPort = try await echo.start()

        let relay = PivotRelay { _ in }
        try relay.start(config: PivotRelay.Config(listenPort: 0, connectHost: "127.0.0.1",
                                                  connectPort: echoPort), allowLoopbackConnect: true) { _ in true }
        let relayPort = try await waitFor(relay.assignedPort, what: "relay listen port")

        // LAN-side payload: connect, say ping, expect the echo server's pong back.
        let answer = try await TCPClient.transact(host: "127.0.0.1", port: relayPort,
                                                  payload: Data("ping".utf8), expectBytes: 4)
        XCTAssertEqual(answer, Data("pong".utf8))
        XCTAssertEqual(echo.received, Data("ping".utf8))

        let stats = try await waitFor(relay.stats.bridged >= 1 ? relay.stats : nil,
                                      what: "bridged stats")
        XCTAssertEqual(stats.bridged, 1)
        XCTAssertGreaterThanOrEqual(stats.up, 4)
        XCTAssertGreaterThanOrEqual(stats.down, 4)
        relay.stop(reason: "test done")
        XCTAssertFalse(relay.isRunning)
    }

    func testRelayRejectsPeersOutsideTheScope() async throws {
        let relay = PivotRelay { _ in }
        // Nothing may be bridged: the peer check refuses everyone.
        try relay.start(config: PivotRelay.Config(listenPort: 0, connectHost: "127.0.0.1",
                                                  connectPort: 9), allowLoopbackConnect: true) { _ in false }
        let relayPort = try await waitFor(relay.assignedPort, what: "relay listen port")

        _ = try? await TCPClient.transact(host: "127.0.0.1", port: relayPort,
                                          payload: Data("letmein".utf8), expectBytes: 1)
        let stats = try await waitFor(relay.stats.rejected >= 1 ? relay.stats : nil,
                                      what: "rejected stats")
        XCTAssertEqual(stats.rejected, 1)
        XCTAssertEqual(stats.bridged, 0, "a rejected peer must never be bridged")
        relay.stop(reason: "test done")
    }

    func testConnectBackValidation() {
        let relay = PivotRelay { _ in }
        XCTAssertThrowsError(try relay.start(
            config: .init(listenPort: 0, connectHost: "", connectPort: 4444)) { _ in true })
        XCTAssertThrowsError(try relay.start(
            config: .init(listenPort: 4444, connectHost: "127.0.0.1", connectPort: 4444)) { _ in true },
                             "loopback is never a connect-back target")
        XCTAssertThrowsError(try relay.start(
            config: .init(listenPort: 4444, connectHost: "ops.example.com", connectPort: 0)) { _ in true })
        XCTAssertNoThrow(try relay.start(
            config: .init(listenPort: 0, connectHost: "ops.example.com", connectPort: 4444)) { _ in true })
        relay.stop(reason: "test done")
    }
}

/// The operator's stand-in: accepts one connection at a time and answers ping with pong.
final class EchoServer: @unchecked Sendable {
    private let queue = DispatchQueue(label: "nero.test.echo")
    private var listener: NWListener?
    private var connection: NWConnection?
    private let lock = NSLock()
    private var _received = Data()
    var received: Data { lock.withLock { _received } }

    func start() async throws -> UInt16 {
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        return try await withCheckedThrowingContinuation { continuation in
            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            listener.stateUpdateHandler = { state in
                if case .ready = state, let port = listener.port?.rawValue {
                    continuation.resume(returning: port)
                }
                if case .failed(let error) = state {
                    continuation.resume(throwing: error)
                }
            }
            listener.start(queue: queue)
        }
    }

    private func accept(_ connection: NWConnection) {
        self.connection = connection
        connection.start(queue: queue)
        receive()
    }

    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, _, error in
            guard let self, error == nil, let data, !data.isEmpty else { return }
            lock.withLock { self._received.append(data) }
            // Answer ping with pong, whatever came in.
            self.connection?.send(content: Data("pong".utf8), completion: .contentProcessed { _ in })
            self.receive()
        }
    }
}

/// A minimal LAN-side payload stand-in: connect, send, read exactly `expectBytes`.
/// Every continuation is guarded so a late timeout cannot double-resume it.
enum TCPClient {
    private final class Resumer: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private let value: (Result<Data, Error>) -> Void
        init(_ resume: @escaping (Result<Data, Error>) -> Void) { value = resume }
        func callAsFunction(_ result: Result<Data, Error>) {
            guard lock.withLock({ () -> Bool in defer { done = true }; return !done }) else { return }
            value(result)
        }
    }

    static func transact(host: String, port: UInt16, payload: Data,
                         expectBytes: Int, timeout: TimeInterval = 5) async throws -> Data {
        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        defer { connection.cancel() }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumer = Resumer { result in
                switch result {
                case .success: continuation.resume()
                case .failure(let error): continuation.resume(throwing: error)
                }
            }
            let queue = DispatchQueue(label: "nero.test.client")
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: resumer(.success(Data()))
                case .failed(let error): resumer(.failure(error))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                resumer(.failure(PivotRelay.PivotError.invalidConfig))
            }
        }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            let resumer = Resumer { result in
                switch result {
                case .success(let data): continuation.resume(returning: data)
                case .failure(let error): continuation.resume(throwing: error)
                }
            }
            let queue = DispatchQueue(label: "nero.test.client.read")
            connection.send(content: payload, completion: .contentProcessed { error in
                if let error { resumer(.failure(error)) }
            })
            var received = Data()
            func read() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: expectBytes) {
                    data, _, isComplete, error in
                    if let data { received.append(data) }
                    if received.count >= expectBytes {
                        resumer(.success(received))
                    } else if let error {
                        resumer(.failure(error))
                    } else if isComplete {
                        resumer(.failure(PivotRelay.PivotError.invalidConfig))
                    } else {
                        read()
                    }
                }
            }
            read()
            queue.asyncAfter(deadline: .now() + timeout) {
                resumer(.failure(PivotRelay.PivotError.invalidConfig))
            }
        }
    }
}
