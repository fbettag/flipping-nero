import Foundation

/// A single IPv4 address with integer comparisons, so scope checks stay cheap.
public struct IPv4Address: Sendable, Equatable, Hashable, Comparable, Codable {
    public let value: UInt32

    public init?(_ string: String) {
        var result: UInt32 = 0
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        for part in parts {
            guard let byte = UInt32(part), part.count <= 3, byte <= 255 else { return nil }
            result = (result << 8) | byte
        }
        value = result
    }

    public init(_ value: UInt32) { self.value = value }

    public init?(data: Data) {
        guard data.count == 4 else { return nil }
        value = data.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    public var string: String {
        "\(value >> 24 & 0xFF).\(value >> 16 & 0xFF).\(value >> 8 & 0xFF).\(value & 0xFF)"
    }

    public var data: Data {
        Data([UInt8(value >> 24 & 0xFF), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
    }

    public static func < (a: IPv4Address, b: IPv4Address) -> Bool { a.value < b.value }
}

/// An IPv4 CIDR block. Refuses prefixes that are too wide to be a sane scope argument.
public struct IPv4CIDR: Sendable, Equatable, Hashable, Codable {
    public let address: IPv4Address
    /// Host bits are zeroed, so 10.0.0.7/24 and 10.0.0.0/24 are the same block.
    public let prefix: Int

    /// Scope arguments smaller than this (a `/19` or wider) are rejected.
    public static let minimumPrefix = 20

    public init?(_ string: String, minimumPrefix: Int = IPv4CIDR.minimumPrefix) {
        let parts = string.split(separator: "/")
        guard parts.count == 2, let address = IPv4Address(String(parts[0])), let prefix = Int(parts[1]),
              (0...32).contains(prefix), prefix >= minimumPrefix else { return nil }
        self.address = IPv4Address(address.value & Self.mask(prefix: prefix))
        self.prefix = prefix
    }

    public init(address: IPv4Address, prefix: Int) {
        self.address = IPv4Address(address.value & Self.mask(prefix: prefix))
        self.prefix = prefix
    }

    public static func mask(prefix: Int) -> UInt32 {
        prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
    }

    public var mask: UInt32 { Self.mask(prefix: prefix) }

    public var string: String { "\(address.string)/\(prefix)" }

    public var hostCount: UInt32 {
        if prefix == 32 { return 1 }
        if prefix == 31 { return 2 }
        return (~mask) &+ 1
    }

    public func contains(_ address: IPv4Address) -> Bool {
        address.value & mask == self.address.value & mask
    }

    public var broadcast: IPv4Address { IPv4Address(address.value | ~mask) }

    /// All host addresses, smallest first, excluding network and broadcast address.
    public var hosts: [IPv4Address] {
        guard prefix < 31 else { return [address] }
        return (1..<UInt32(hostCount) - 1).map { IPv4Address(address.value + $0) }
    }
}

/// The hard per-call limits. One `/8` is not a valid argument; neither is scanning 50k ports.
public struct ScopeCaps: Sendable, Equatable, Codable {
    public var maxHosts = 256
    public var maxPorts = 100
    public var maxConcurrency = 32
    public var maxTimeout: Duration = .seconds(5)
    public var maxHTTPBody = 4 * 1024
    public var maxBannerBytes = 2 * 1024

    public init() {}
}

/// Session capabilities the operator arms. The agent can ask for them,
/// but only the human arm dialog (or an approved `set_engagement` call) applies them.
public struct Capabilities: Sendable, Equatable, Codable {
    /// Medium- and high-risk actions run without a per-action prompt. Blocked actions stay blocked.
    public var autoApprovals: Bool
    /// Unlocks `exploit_check` and `exploit_run`.
    public var exploit: Bool
    /// Unlocks talking to a Field Node. Reserved for the pivot; nothing in v1 uses it yet.
    public var pivot: Bool
    /// Unlocks explicitly targeted link-local addresses such as a cloud metadata endpoint.
    public var cloudReadonly: Bool

    public init(autoApprovals: Bool = true, exploit: Bool = false, pivot: Bool = false, cloudReadonly: Bool = false) {
        self.autoApprovals = autoApprovals
        self.exploit = exploit
        self.pivot = pivot
        self.cloudReadonly = cloudReadonly
    }

    public var summary: String {
        var parts: [String] = []
        if autoApprovals { parts.append("auto_approvals") }
        if exploit { parts.append("exploit") }
        if pivot { parts.append("pivot") }
        if cloudReadonly { parts.append("cloud_readonly") }
        return parts.isEmpty ? "none" : parts.joined(separator: "+")
    }
}

/// The run may touch the network only inside this window; nil means open-ended.
public struct TimeWindow: Sendable, Equatable, Codable {
    public var start: Date
    public var end: Date

    public init(start: Date, end: Date) {
        self.start = start
        self.end = end
    }

    public func contains(_ date: Date) -> Bool { date >= start && date <= end }
}

/// The scope a run is allowed to touch. Without a scope every network tool is blocked.
/// Session-only: the app drops it on disconnect, expiry or app kill.
public struct ScopePolicy: Sendable, Equatable, Codable {
    /// CIDR allowlist. Empty means nothing is in scope.
    public var cidrs: [IPv4CIDR]
    /// Host denylist; wins over the allowlist.
    public var denyHosts: Set<IPv4Address>
    /// UInt16 allowlist. Empty means no port may be touched.
    public var ports: Set<UInt16>
    public var window: TimeWindow?
    public var caps = ScopeCaps()
    public var capabilities = Capabilities()
    /// Free-text note from the operator, shown on the banner and given to the agent.
    public var note: String

    /// Loopback, multicast, reserved and the top of the link-local block are never in scope.
    static let neverAllowed: [(IPv4CIDR, String)] = [
        (IPv4CIDR("127.0.0.0/8", minimumPrefix: 0)!, "loopback"),
        (IPv4CIDR("224.0.0.0/4", minimumPrefix: 0)!, "multicast"),
        (IPv4CIDR("240.0.0.0/4", minimumPrefix: 0)!, "reserved"),
        (IPv4CIDR("0.0.0.0/8", minimumPrefix: 0)!, "this-host"),
    ]
    /// Link-local: blocked, except a single explicitly targeted host under `cloud_readonly`.
    static let linkLocal = IPv4CIDR("169.254.0.0/16", minimumPrefix: 0)!
    public static let cloudMetadata = IPv4Address("169.254.169.254")

    public init(cidrs: [IPv4CIDR] = [], denyHosts: Set<IPv4Address> = [], ports: Set<UInt16> = [],
                window: TimeWindow? = nil, caps: ScopeCaps = ScopeCaps(),
                capabilities: Capabilities = Capabilities(), note: String = "") {
        self.cidrs = cidrs
        self.denyHosts = denyHosts
        self.ports = ports
        self.window = window
        self.caps = caps
        self.capabilities = capabilities
        self.note = String(TextSanitizer.sanitizeName(note).prefix(200))
    }

    /// The scope the Run tap starts with: the current interface subnet and the default port set.
    public static func localSubnet(_ cidr: IPv4CIDR, startedAt: Date = Date(),
                                   ports: Set<UInt16> = Set(PortPreset.top100)) -> ScopePolicy {
        ScopePolicy(cidrs: [cidr], ports: ports,
                    window: TimeWindow(start: startedAt, end: startedAt.addingTimeInterval(12 * 3600)),
                    note: "auto: interface subnet")
    }

    public var isArmed: Bool { !cidrs.isEmpty && !ports.isEmpty }

    /// True when `other` would allow something this policy does not (used by `set_scope`:
    /// loosening always needs the consent dialog, tightening does not).
    public func isLoosening(_ other: ScopePolicy) -> Bool {
        // A block is covered when an existing block is the same network or a supernet of it.
        for cidr in other.cidrs
        where !cidrs.contains(where: { $0.address.value == cidr.address.value && $0.prefix <= cidr.prefix }) {
            return true
        }
        if !denyHosts.isSubset(of: other.denyHosts) { return true }
        if !other.ports.isSubset(of: ports) { return true }
        if window != nil, other.window == nil { return true }
        if let end = window?.end, let otherEnd = other.window?.end, otherEnd > end { return true }
        return false
    }
}

/// Everything the scope check can answer before a byte leaves the phone.
public enum ScopeVerdict: Sendable, Equatable {
    case ok
    case blocked(String)
}

/// Deterministic gate between a parsed tool call and the network.
/// Nothing reaches a socket unless `check` said ok for every target in the call.
public enum ScopeGuard {
    public static func check(_ targets: [ScopeTarget], policy: ScopePolicy?, now: Date = Date()) -> ScopeVerdict {
        guard let policy else { return .blocked("no scope is set; start a run or set one with set_scope") }
        guard policy.isArmed else { return .blocked("scope has no networks or no ports") }
        if let window = policy.window, !window.contains(now) {
            return .blocked(now < window.start
                ? "scope is not open yet"
                : "scope time window has expired; the run is disarmed")
        }
        for target in targets {
            switch target {
            case .host(let address):
                if let verdict = checkHost(address, policy: policy, explicit: true) { return verdict }
            case .hosts(let cidr, let count):
                guard count <= policy.caps.maxHosts else {
                    return .blocked("\(count) hosts exceed the per-call cap of \(policy.caps.maxHosts); use a smaller block")
                }
                guard cidr.hostCount <= policy.caps.maxHosts else {
                    return .blocked("\(cidr.string) holds \(cidr.hostCount) hosts, more than the per-call cap of \(policy.caps.maxHosts)")
                }
                guard policy.cidrs.contains(where: { $0.address.value == cidr.address.value && $0.prefix <= cidr.prefix }) else {
                    return .blocked("\(cidr.string) is outside the scope allowlist")
                }
                if let verdict = checkBlock(cidr) { return verdict }
            case .port(let port):
                guard policy.ports.contains(port) else {
                    return .blocked("port \(port) is not in the port allowlist")
                }
            case .ports(let ports):
                if let denied = ports.first(where: { !policy.ports.contains($0) }) {
                    return .blocked("port \(denied) is not in the port allowlist")
                }
            case .url(let host, let port):
                if let verdict = checkHost(host, policy: policy, explicit: true) { return verdict }
                guard policy.ports.contains(port) else {
                    return .blocked("port \(port) is not in the port allowlist")
                }
            case .name(let name):
                // DNS names are checked after resolution against the resolved addresses;
                // the resolution call itself is allowed (it goes to the configured resolver, not the target).
                guard !name.isEmpty, name.utf8.count <= 253 else { return .blocked("invalid name") }
            case .local:
                break
            }
        }
        return .ok
    }

    /// Returns a verdict when the host is out of scope, nil when it may be touched.
    /// `explicit` is true when the operator or agent named this exact host in the call.
    public static func checkHost(_ address: IPv4Address, policy: ScopePolicy, explicit: Bool) -> ScopeVerdict? {
        if let verdict = checkNever(address) { return verdict }
        if policy.denyHosts.contains(address) { return .blocked("\(address.string) is on the denylist") }
        if ScopePolicy.linkLocal.contains(address) {
            guard explicit, policy.capabilities.cloudReadonly else {
                return .blocked("link-local addresses are blocked (capability cloud_readonly not armed)")
            }
            return nil
        }
        guard policy.cidrs.contains(where: { $0.contains(address) }) else {
            return .blocked("\(address.string) is outside the scope allowlist")
        }
        return nil
    }

    static func checkNever(_ address: IPv4Address) -> ScopeVerdict? {
        for (block, why) in ScopePolicy.neverAllowed where block.contains(address) {
            return .blocked("\(address.string) is \(why) and never in scope")
        }
        return nil
    }

    /// A whole address block must not overlap the ranges that are never in scope,
    /// and discovery must never sweep link-local even when single hosts could.
    static func checkBlock(_ cidr: IPv4CIDR) -> ScopeVerdict? {
        for (block, why) in ScopePolicy.neverAllowed where cidr.contains(block.address) || block.contains(cidr.address) {
            return .blocked("\(cidr.string) overlaps \(why) addresses")
        }
        if ScopePolicy.linkLocal.contains(cidr.address) || cidr.contains(ScopePolicy.linkLocal.address) {
            return .blocked("\(cidr.string) overlaps link-local; sweep blocks may not include it")
        }
        return nil
    }
}

/// A target extracted from a validated tool call, in the terms the scope speaks.
public enum ScopeTarget: Sendable, Equatable {
    case host(IPv4Address)
    case hosts(IPv4CIDR, count: Int)
    case port(UInt16)
    case ports([UInt16])
    case url(host: IPv4Address, port: UInt16)
    case name(String)
    /// The phone's own context (interface, resolvers); never leaves the device.
    case local
}
