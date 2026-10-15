import Foundation

/// Credential spraying against one host, with fixed bundle lists and a rate limit.
/// No open wordlist tool in v1: the bundles below are the complete supply, so a run
/// cannot grind through thousands of guesses.
public enum AuthSpray {
    /// The full HTTP basic-auth bundle. Eight pairs, no parameter can grow it.
    public static let httpPairs: [(user: String, password: String)] = [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("root", "root"),
        ("admin", "12345678"), ("user", "user"), ("operator", "operator"), ("service", "service"),
    ]
    /// The full Redis password bundle.
    public static let redisPasswords: [String] = [
        "redis", "password", "admin", "12345678", "changeme", "foobared", "redis123", "letmein",
    ]

    /// Minimum seconds between two attempts against the same host.
    public static let minInterval: TimeInterval = 1.0

    public struct Attempt: Sendable, Equatable {
        public var user: String?
        public var password: String
        public var accepted: Bool
        public var detail: String
    }

    public struct Result: Sendable, Equatable {
        public var attempts: [Attempt]
        public var accepted: Attempt?
        public var evidence: [String]
    }

    /// HTTP basic auth, one fixed path, eight fixed pairs, one per second.
    public static func httpBasic(host: IPv4Address, port: UInt16, path: String, probe: NetworkProbe,
                                 caps: ScopeCaps) async -> Result {
        let scheme = port == 443 ? "https" : "http"
        let cleanPath = path.hasPrefix("/") ? path : "/" + path
        var attempts: [Attempt] = []
        var evidence: [String] = []
        for (index, pair) in httpPairs.enumerated() {
            if index > 0 { try? await Task.sleep(for: .milliseconds(Int(minInterval * 1000))) }
            let credential = Data("\(pair.user):\(pair.password)".utf8).base64EncodedString()
            guard let url = URL(string: "\(scheme)://\(host.string):\(port)\(cleanPath)") else { break }
            let response = try? await probe.http(
                HTTPRequestSpec(method: "GET", url: url, headers: ["Authorization": "Basic \(credential)"]),
                timeout: min(.seconds(3), caps.maxTimeout))
            let status = response?.status ?? 0
            let accepted = (200..<300).contains(status)
            attempts.append(Attempt(user: pair.user, password: pair.password, accepted: accepted,
                                    detail: "HTTP \(status)"))
            // Passwords stay out of evidence; the accepted pair lands in the loot store.
            evidence.append("\(pair.user):*** -> HTTP \(status)")
            if accepted { break }
        }
        return Result(attempts: attempts, accepted: attempts.first(where: \.accepted), evidence: evidence)
    }

    /// Redis AUTH, fixed password bundle, one per second.
    public static func redis(host: IPv4Address, port: UInt16, probe: NetworkProbe, caps: ScopeCaps) async -> Result {
        var attempts: [Attempt] = []
        var evidence: [String] = []
        for (index, password) in redisPasswords.enumerated() {
            if index > 0 { try? await Task.sleep(for: .milliseconds(Int(minInterval * 1000))) }
            let reply = await probe.exchange(host, port: port,
                                             send: Data("AUTH \(password)\r\n".utf8),
                                             timeout: min(.seconds(2), caps.maxTimeout),
                                             maxBytes: caps.maxBannerBytes)
            let text = reply.map { TextSanitizer.clean(String(decoding: $0.prefix(120), as: UTF8.self)) } ?? ""
            let accepted = text.contains("+OK")
            attempts.append(Attempt(user: nil, password: password, accepted: accepted,
                                    detail: text.isEmpty ? "no reply" : String(text.prefix(60))))
            evidence.append("AUTH *** -> \(text.isEmpty ? "no reply" : String(text.prefix(40)))")
            if accepted { break }
        }
        return Result(attempts: attempts, accepted: attempts.first(where: \.accepted), evidence: evidence)
    }
}
