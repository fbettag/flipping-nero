import Foundation
import Network

/// A TCP relay that turns the phone into a pivot for an operator-side handler:
/// it listens inside the LAN, and every accepted peer the scope allows is bridged
/// byte-for-byte to the configured connect-back host outside. Point payloads at the
/// phone's LAN address and the listen port; the handler on the operator side sees the
/// sessions as if it were reachable itself.
///
/// Operator-only by design: started and stopped by a human in Settings (with the pivot
/// capability armed), never by the agent. The LAN side is scope-guarded: peers outside
/// the CIDR allowlist are dropped and counted.
public final class PivotRelay: @unchecked Sendable {
    public struct Config: Sendable, Equatable {
        /// LAN side. 0 asks the system for an ephemeral port (tests); the app passes a real one.
        public var listenPort: UInt16
        /// Operator side, the host the relay dials out to (handler/listener address).
        public var connectHost: String
        public var connectPort: UInt16

        public init(listenPort: UInt16, connectHost: String, connectPort: UInt16) {
            self.listenPort = listenPort
            self.connectHost = connectHost
            self.connectPort = connectPort
        }
    }

    public struct Stats: Sendable, Equatable {
        /// Sessions accepted and bridged.
        public var bridged = 0
        /// Currently piping.
        public var active = 0
        /// Peers dropped because the scope does not cover them.
        public var rejected = 0
        /// Bytes LAN -> operator.
        public var up = 0
        /// Bytes operator -> LAN.
        public var down = 0
        public init() {}
    }

    public enum Event: Sendable {
        case started(Config)
        case bridged(peer: String)
        case rejected(peer: String)
        case closed(peer: String, up: Int, down: Int, reason: String)
        case failed(String)
        case stopped(reason: String)
    }

    public enum PivotError: Error, CustomStringConvertible {
        case invalidConfig
        case invalidConnectHost
        public var description: String {
            switch self {
            case .invalidConfig: "connect host, listen port or connect port is missing or invalid"
            case .invalidConnectHost: "the connect-back host is an address this relay refuses to dial (loopback, multicast, reserved)"
            }
        }
    }

    static let queue = DispatchQueue(label: "nero.pivot")
    private let lock = NSLock()
    private var listener: NWListener?
    private var bridges: [ObjectIdentifier: Bridge] = [:]
    private var _stats = Stats()
    private let onEvent: @Sendable (Event) -> Void

    public init(onEvent: @escaping @Sendable (Event) -> Void) {
        self.onEvent = onEvent
    }

    public var stats: Stats { lock.withLock { _stats } }
    public var isRunning: Bool { lock.withLock { listener } != nil }
    /// The port actually bound; nil until the listener is ready (an ephemeral request
    /// reports `.any`, i.e. 0, until then).
    public var assignedPort: UInt16? {
        guard let port = lock.withLock({ listener })?.port?.rawValue, port != 0 else { return nil }
        return port
    }

    public func start(config: Config, peerAllowed: @escaping @Sendable (IPv4Address) -> Bool,
                      allowLoopbackConnect: Bool = false) throws {
        guard !isRunning else { return }
        let host = config.connectHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty,
              (1...65535).contains(Int(config.connectPort)),
              (0...65535).contains(Int(config.listenPort)) else {
            throw PivotError.invalidConfig
        }
        // A dial-out address that is never a real operator host is a misconfiguration.
        // Tests run against localhost and pass the flag.
        if let address = IPv4Address(host),
           !allowLoopbackConnect || !address.string.hasPrefix("127."),
           Self.isNeverTarget(address) {
            throw PivotError.invalidConnectHost
        }
        guard let listenEndpoint = NWEndpoint.Port(rawValue: config.listenPort == 0 ? 0 : config.listenPort) else {
            throw PivotError.invalidConfig
        }
        let newListener = try NWListener(using: .tcp, on: listenEndpoint)
        newListener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection, config: config, peerAllowed: peerAllowed)
        }
        newListener.stateUpdateHandler = { [weak self] state in
            guard let self, case .failed(let error) = state else { return }
            self.onEvent(.failed("listener failed: \(error)"))
            self.stop(reason: "listener failed")
        }
        lock.withLock { listener = newListener }
        newListener.start(queue: Self.queue)
        onEvent(.started(config))
    }

    public func stop(reason: String) {
        let (current, active) = lock.withLock { () -> (NWListener?, [Bridge]) in
            let listener = self.listener
            self.listener = nil
            let bridges = Array(self.bridges.values)
            self.bridges.removeAll()
            _stats.active = 0
            return (listener, bridges)
        }
        current?.cancel()
        for bridge in active {
            Self.queue.async { bridge.finish("relay stopped") }
        }
        onEvent(.stopped(reason: reason))
    }

    // MARK: accepting LAN-side peers

    private func accept(_ lan: NWConnection, config: Config,
                        peerAllowed: @escaping @Sendable (IPv4Address) -> Bool) {
        var bridge: Bridge?
        lan.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard bridge == nil else { return }
                let peer = Self.remoteHost(of: lan) ?? "?"
                guard let address = IPv4Address(peer), peerAllowed(address) else {
                    lock.withLock { self._stats.rejected += 1 }
                    onEvent(.rejected(peer: peer))
                    lan.cancel()
                    return
                }
                let upstream = NWConnection(host: NWEndpoint.Host(config.connectHost),
                                            port: NWEndpoint.Port(rawValue: config.connectPort)!,
                                            using: .tcp)
                let newBridge = Bridge(lan: lan, upstream: upstream, peer: peer,
                                       queue: Self.queue,
                                       onClosed: { [weak self] peer, up, down, reason in
                                           self?.bridgeClosed(peer: peer, up: up, down: down, reason: reason)
                                       },
                                       onBytes: { [weak self] up, down in
                                           self?.lock.withLock {
                                               self?._stats.up += up
                                               self?._stats.down += down
                                           }
                                       })
                newBridge.onDone = { [weak self, weak newBridge] in
                    guard let self, let newBridge else { return }
                    self.lock.withLock { _ = self.bridges.removeValue(forKey: ObjectIdentifier(newBridge)) }
                }
                bridge = newBridge
                lock.withLock {
                    self._stats.bridged += 1
                    self._stats.active += 1
                    self.bridges[ObjectIdentifier(newBridge)] = newBridge
                }
                onEvent(.bridged(peer: peer))
                newBridge.start()
            case .failed(let error):
                bridge?.finish("lan connection failed: \(error)")
                if bridge == nil { lan.cancel() }
            case .cancelled:
                bridge?.finish("lan connection cancelled")
            default:
                break
            }
        }
        lan.start(queue: Self.queue)
    }

    private func bridgeClosed(peer: String, up: Int, down: Int, reason: String) {
        // Byte totals already flowed in live via onBytes; closing only releases the slot.
        lock.withLock { _stats.active = max(0, _stats.active - 1) }
        onEvent(.closed(peer: peer, up: up, down: down, reason: reason))
    }

    static func isNeverTarget(_ address: IPv4Address) -> Bool {
        ScopePolicy.neverAllowed.contains { $0.0.contains(address) }
    }

    static func remoteHost(of connection: NWConnection) -> String? {
        if case .hostPort(let host, _)? = connection.currentPath?.remoteEndpoint,
           case .ipv4(let address) = host {
            return address.debugDescription
        }
        return nil
    }
}

/// One bridged session: the accepted LAN connection and the dialed operator connection,
/// piped in both directions. All callbacks arrive on the relay's serial queue, so the
/// mutable state needs no locks.
final class Bridge: @unchecked Sendable {
    private let lan: NWConnection
    private let upstream: NWConnection
    private let peer: String
    private let queue: DispatchQueue
    private let onClosed: @Sendable (String, Int, Int, String) -> Void
    private let onBytes: @Sendable (Int, Int) -> Void
    var onDone: (() -> Void)?

    private var done = false
    private var piping = false
    private var upstreamReady = false
    private var up = 0
    private var down = 0

    init(lan: NWConnection, upstream: NWConnection, peer: String, queue: DispatchQueue,
         onClosed: @escaping @Sendable (String, Int, Int, String) -> Void,
         onBytes: @escaping @Sendable (Int, Int) -> Void) {
        self.lan = lan
        self.upstream = upstream
        self.peer = peer
        self.queue = queue
        self.onClosed = onClosed
        self.onBytes = onBytes
    }

    /// The LAN side is already connected when the bridge is created; the dial-out starts here.
    func start() {
        upstream.stateUpdateHandler = { [weak self] state in
            guard let self, !self.done else { return }
            switch state {
            case .ready:
                self.upstreamReady = true
                self.beginPipingIfNeeded()
            case .failed(let error):
                self.finish("connect-back failed: \(error)")
            case .cancelled:
                self.finish("connect-back cancelled")
            default:
                break
            }
        }
        upstream.start(queue: queue)
    }

    private func beginPipingIfNeeded() {
        guard upstreamReady, !piping, !done else { return }
        piping = true
        receiveLan()
        receiveUpstream()
    }

    private func receiveLan() {
        guard !done else { return }
        lan.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self, !self.done else { return }
            if let error { self.finish("lan read failed: \(error)"); return }
            if let data, !data.isEmpty {
                self.up += data.count
                self.onBytes(data.count, 0)
                self.upstream.send(content: data, completion: .contentProcessed { [weak self] error in
                    guard let self, !self.done else { return }
                    if let error { self.finish("operator write failed: \(error)"); return }
                    self.receiveLan()
                })
                return
            }
            if isComplete { self.finish("lan side closed"); return }
            self.receiveLan()
        }
    }

    private func receiveUpstream() {
        guard !done else { return }
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self, !self.done else { return }
            if let error { self.finish("operator read failed: \(error)"); return }
            if let data, !data.isEmpty {
                self.down += data.count
                self.onBytes(0, data.count)
                self.lan.send(content: data, completion: .contentProcessed { [weak self] error in
                    guard let self, !self.done else { return }
                    if let error { self.finish("lan write failed: \(error)"); return }
                    self.receiveUpstream()
                })
                return
            }
            if isComplete { self.finish("operator side closed"); return }
            self.receiveUpstream()
        }
    }

    func finish(_ reason: String) {
        guard !done else { return }
        done = true
        lan.cancel()
        upstream.cancel()
        let onDone = self.onDone
        self.onDone = nil
        onClosed(peer, up, down, reason)
        queue.async { onDone?() }
    }
}
