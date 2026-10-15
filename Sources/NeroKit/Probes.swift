import Foundation
import Network

/// iOS allows no raw sockets: TCP is a full connect (NWConnection), ICMP goes over
/// SOCK_DGRAM + IPPROTO_ICMP, HTTP over URLSession with redirects refused. Everything
/// the tools touch is behind this protocol, so tests run against a fake with canned wires.
public protocol NetworkProbe: Sendable {
    /// True when the TCP connection could be established.
    func tcpConnect(_ host: IPv4Address, port: UInt16, timeout: Duration) async -> Bool
    /// True when the host answers an ICMP echo.
    func ping(_ host: IPv4Address, timeout: Duration) async -> Bool
    /// Connects and reads whatever arrives first (SMTP/FTP/HTTP banners, Redis, memcached).
    func readBanner(_ host: IPv4Address, port: UInt16, timeout: Duration, maxBytes: Int) async -> Data?
    /// Connects, sends, reads the answer (probe handshakes for exploit checks).
    func exchange(_ host: IPv4Address, port: UInt16, send: Data, timeout: Duration,
                  maxBytes: Int) async -> Data?
    /// One HTTP request; 3xx responses are returned as-is, never followed.
    func http(_ spec: HTTPRequestSpec, timeout: Duration) async throws -> HTTPResponse
    func queryDNS(_ name: String, rrtype: UInt16, timeout: Duration) async throws -> [DNSRecord]
    /// Browses declared Bonjour service types and resolves name, port and TXT.
    func browseBonjour(_ types: [String], timeout: Duration) async -> [BonjourService]
}

public struct HTTPRequestSpec: Sendable, Equatable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?

    public init(method: String, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponse: Sendable, Equatable {
    public var status: Int
    public var headers: [String: String]
    public var body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    /// The server banner line, e.g. `Server: nginx/1.24.0`.
    public var serverHeader: String? { headers["server"] }
    /// Body as lossy text, capped for evidence use.
    public func text(maxBytes: Int = 2 * 1024) -> String {
        String(decoding: body.prefix(maxBytes), as: UTF8.self)
    }
}

public struct DNSRecord: Sendable, Equatable {
    public let name: String
    public let rrtype: UInt16
    public let data: Data
    public init(name: String, rrtype: UInt16, data: Data) {
        self.name = name
        self.rrtype = rrtype
        self.data = data
    }

    public static let a: UInt16 = 1, ptr: UInt16 = 12, txt: UInt16 = 16, aaaa: UInt16 = 28, srv: UInt16 = 33

    /// Best-effort text form of the record (address, name, port or TXT strings).
    public var text: String {
        switch rrtype {
        case DNSRecord.a: return IPv4Address(data: data)?.string ?? data.base64EncodedString()
        case DNSRecord.aaaa: return Self.ipv6String(from: data)
        case DNSRecord.ptr, DNSRecord.srv:
            let parts = Self.parseName(from: data, offset: rrtype == DNSRecord.srv ? 6 : 0)
            if rrtype == DNSRecord.ptr { return parts.string }
            if parts.offset > 0, data.count >= parts.offset {
                let port = (UInt16(data[data.index(data.startIndex, offsetBy: 4)]) << 8)
                    | UInt16(data[data.index(data.startIndex, offsetBy: 5)])
                return "port \(port) target \(parts.string)"
            }
            return parts.string
        case DNSRecord.txt:
            var lines: [String] = []
            var i = 0
            let d = data
            while i < d.count {
                let length = Int(d[d.startIndex + i])
                i += 1
                guard i + length <= d.count else { break }
                lines.append(String(decoding: d[(d.startIndex + i)..<(d.startIndex + i + length)], as: UTF8.self))
                i += length
            }
            return lines.joined(separator: "; ")
        default: return data.base64EncodedString()
        }
    }

    static func ipv6String(from data: Data) -> String {
        guard data.count == 16 else { return data.base64EncodedString() }
        return (0..<8).map { i in
            let hi = data[data.startIndex + i * 2], lo = data[data.startIndex + i * 2 + 1]
            return String(format: "%02x%02x", hi, lo)
        }.joined(separator: ":")
    }

    /// Reads DNS name labels from `offset`; a compression pointer ends the name (best effort).
    static func parseName(from data: Data, offset: Int) -> (string: String, offset: Int) {
        var labels: [String] = []
        var i = offset
        let d = data
        while i < d.count {
            let length = Int(d[d.startIndex + i])
            if length == 0 { i += 1; break }
            if length & 0xC0 == 0xC0 { i += 2; break }
            i += 1
            guard i + length <= d.count else { break }
            labels.append(String(decoding: d[(d.startIndex + i)..<(d.startIndex + i + length)], as: UTF8.self))
            i += length
        }
        return (labels.joined(separator: "."), i)
    }
}

public struct BonjourService: Sendable, Equatable {
    public var name: String
    public var type: String
    public var domain: String
    public var port: UInt16
    public var txt: [String]

    public init(name: String, type: String, domain: String, port: UInt16, txt: [String] = []) {
        self.name = name
        self.type = type
        self.domain = domain
        self.port = port
        self.txt = txt
    }

    public var summary: String {
        let txt = txt.isEmpty ? "" : " txt: \(TextSanitizer.clean(txt.joined(separator: "; "), maxLength: 300))"
        return "\(TextSanitizer.sanitizeName(name)) [\(type)] port \(port)\(txt)"
    }
}

public enum ProbeError: Error, CustomStringConvertible {
    case timeout(String)
    case refused
    case aborted
    public var description: String {
        switch self {
        case .timeout(let what): "timeout during \(what)"
        case .refused: "connection refused"
        case .aborted: "connection aborted"
        }
    }
}

/// Delivers a continuation exactly once from racing callbacks.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    /// Returns true when this call won the race and `body` ran.
    @discardableResult
    func once(_ body: () -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !done else { return false }
        done = true
        body()
        return true
    }
}

/// The real network layer. Works on-device and in the simulator; the sandbox changes nothing.
public struct NWProbe: NetworkProbe {
    static let queue = DispatchQueue(label: "nero.probe", qos: .utility)

    /// Answers whether an https host may present a self-signed certificate. LAN services
    /// almost never carry publicly trusted certs, so the app allows it exactly for hosts
    /// the scope covers; everything else needs a valid chain. Re-checked at handshake
    /// time, not just at request time.
    private let httpSession: URLSession

    public init(hostInScope: @escaping @Sendable (String) -> Bool = { _ in false }) {
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.httpSession = URLSession(configuration: config,
                                      delegate: HTTPSessionDelegate(hostInScope: hostInScope),
                                      delegateQueue: nil)
    }

    public func tcpConnect(_ host: IPv4Address, port: UInt16, timeout: Duration) async -> Bool {
        let connection = Self.connection(to: host, port: port)
        defer { connection.cancel() }
        do {
            try await Self.waitReady(connection, timeout: timeout)
            return true
        } catch {
            return false
        }
    }

    public func ping(_ host: IPv4Address, timeout: Duration) async -> Bool {
        await ICMPProber.ping(host, timeout: timeout)
    }

    public func readBanner(_ host: IPv4Address, port: UInt16, timeout: Duration,
                           maxBytes: Int) async -> Data? {
        let connection = Self.connection(to: host, port: port)
        defer { connection.cancel() }
        guard (try? await Self.waitReady(connection, timeout: timeout)) != nil else { return nil }
        return await Self.read(connection, deadline: .now + timeout, maxBytes: maxBytes)
    }

    public func exchange(_ host: IPv4Address, port: UInt16, send: Data, timeout: Duration,
                         maxBytes: Int) async -> Data? {
        let connection = Self.connection(to: host, port: port)
        defer { connection.cancel() }
        guard (try? await Self.waitReady(connection, timeout: timeout)) != nil else { return nil }
        guard let received = await Self.send(connection, data: send, deadline: .now + timeout) else { return nil }
        return await Self.read(connection, deadline: .now + timeout, maxBytes: maxBytes, after: received)
    }

    public func http(_ spec: HTTPRequestSpec, timeout: Duration) async throws -> HTTPResponse {
        var request = URLRequest(url: spec.url)
        request.httpMethod = spec.method
        request.timeoutInterval = Double(timeout.components.seconds)
        request.httpBody = spec.body
        for (key, value) in spec.headers { request.setValue(value, forHTTPHeaderField: key) }
        let (data, response) = try await httpSession.data(for: request)
        let http = response as? HTTPURLResponse
        var headers: [String: String] = [:]
        for (key, value) in http?.allHeaderFields ?? [:] {
            if let key = key as? String, let value = value as? String { headers[key.lowercased()] = value }
        }
        return HTTPResponse(status: http?.statusCode ?? 0, headers: headers, body: data)
    }

    public func queryDNS(_ name: String, rrtype: UInt16, timeout: Duration) async throws -> [DNSRecord] {
        try await DNSResolver.query(name: name, rrtype: rrtype, timeout: timeout)
    }

    public func browseBonjour(_ types: [String], timeout: Duration) async -> [BonjourService] {
        await BonjourResolver.browseAndResolve(types: types, timeout: timeout)
    }

    // MARK: plumbing

    static func connection(to host: IPv4Address, port: UInt16) -> NWConnection {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host.string),
                                           port: NWEndpoint.Port(rawValue: port)!)
        return NWConnection(to: endpoint, using: .tcp)
    }

    /// Redirects are refused (what the scope checked is what gets contacted) and self-signed
    /// certificates are accepted only for hosts the scope covers.
    final class HTTPSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let hostInScope: @Sendable (String) -> Bool
        init(hostInScope: @escaping @Sendable (String) -> Bool) {
            self.hostInScope = hostInScope
        }

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                        completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
            completionHandler(nil)
        }

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            var error: CFError?
            if SecTrustEvaluateWithError(trust, &error) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            if hostInScope(challenge.protectionSpace.host) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }

    static func waitReady(_ connection: NWConnection, timeout: Duration) async throws {
        let seconds = TimeInterval(timeout.components.seconds) + Double(timeout.components.attoseconds) / 1e18
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let once = ResumeOnce()
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: once.once { cont.resume() }
                case .failed(let error): once.once { cont.resume(throwing: error) }
                case .cancelled: once.once { cont.resume(throwing: ProbeError.aborted) }
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: DispatchTime.now() + seconds) {
                // Only tear the connection down when the timeout won the race;
                // a later unconditional cancel would kill reads that are still wanted.
                if once.once({ cont.resume(throwing: ProbeError.timeout("connect")) }) {
                    connection.cancel()
                }
            }
        }
    }

    static func send(_ connection: NWConnection, data: Data, deadline: ContinuousClock.Instant) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            let once = ResumeOnce()
            connection.send(content: data, completion: .contentProcessed { error in
                once.once { cont.resume(returning: error == nil ? data : nil) }
            })
            queue.asyncAfter(deadline: DispatchTime.now() + remaining(deadline)) {
                if once.once({ cont.resume(returning: nil) }) {
                    connection.cancel()
                }
            }
        }
    }

    static func read(_ connection: NWConnection, deadline: ContinuousClock.Instant,
                     maxBytes: Int, after initial: Data = Data()) async -> Data {
        var data = initial
        while data.count < maxBytes, deadline - .now > .zero {
            let chunk: Data? = await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
                let once = ResumeOnce()
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxBytes - data.count) {
                    content, _, isComplete, _ in
                    once.once {
                        if let content, !content.isEmpty { cont.resume(returning: content) }
                        else { cont.resume(returning: nil) }
                    }
                }
                queue.asyncAfter(deadline: DispatchTime.now() + remaining(deadline)) {
                    if once.once({ cont.resume(returning: nil) }) {
                        connection.cancel()
                    }
                }
            }
            guard let chunk else { break }
            data.append(chunk)
        }
        return data.prefix(maxBytes)
    }

    static func remaining(_ deadline: ContinuousClock.Instant) -> TimeInterval {
        let duration = deadline - .now
        let seconds = Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
        return max(0.05, seconds)
    }
}

/// ICMP echo over SOCK_DGRAM + IPPROTO_ICMP: the only ICMP iOS allows. No SOCK_RAW, no /dev/bpf.
enum ICMPProber {
    static let identifier = UInt16.random(in: 1...0xFFFF)

    static func ping(_ host: IPv4Address, timeout: Duration) async -> Bool {
        let seconds = Double(timeout.components.seconds) + Double(timeout.components.attoseconds) / 1e18
        return await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                cont.resume(returning: blockingPing(host, seconds: seconds))
            }
        }
    }

    static func blockingPing(_ host: IPv4Address, seconds: TimeInterval) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(seconds), tv_usec: Int32((seconds.truncatingRemainder(dividingBy: 1)) * 1_000_000))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let sequence = UInt16.random(in: 1...0xFFFF)
        var packet = Data(count: 8 + 24)
        packet[0] = 8 // ICMP echo request
        packet[2] = UInt8(identifier >> 8)
        packet[3] = UInt8(identifier & 0xFF)
        packet[4] = UInt8(sequence >> 8)
        packet[5] = UInt8(sequence & 0xFF)
        let checksum = Self.checksum(packet)
        packet[6] = UInt8(checksum >> 8)
        packet[7] = UInt8(checksum & 0xFF)

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: host.value.bigEndian)
        let sent = packet.withUnsafeBytes { buffer -> Int in
            withUnsafePointer(to: &addr) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    sendto(fd, buffer.baseAddress, buffer.count, 0, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == packet.count else { return false }

        var reply = Data(count: 1500)
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        var source = sockaddr_in()
        let received = reply.withUnsafeMutableBytes { buffer -> Int in
            withUnsafeMutablePointer(to: &source) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    recvfrom(fd, buffer.baseAddress, buffer.count, 0, sockaddrPointer, &addrLen)
                }
            }
        }
        guard received >= 20 else { return false }
        // Type 0 is an echo reply; match our own identifier so unrelated ICMP does not count.
        return reply[0] == 0 && UInt16(reply[2]) << 8 | UInt16(reply[3]) == identifier
    }

    static func checksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        let bytes = [UInt8](data)
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }
}
