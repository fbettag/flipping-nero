import Foundation

/// One IPv4 interface with its subnet, as getifaddrs reports it.
public struct NetworkInterface: Sendable, Equatable {
    public let name: String
    public let address: IPv4Address
    public let prefix: Int
    public let broadcast: IPv4Address?

    public var cidr: IPv4CIDR { IPv4CIDR(address: address, prefix: prefix) }
}

/// The phone's own network context: interfaces, the primary subnet and the default gateway.
/// This never leaves the device; `get_network_context` reports it to the model.
public enum NetworkContext {
    public static func interfaces() -> [NetworkInterface] {
        var result: [NetworkInterface] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return result }
        defer { freeifaddrs(ifaddr) }
        var pointer: UnsafeMutablePointer<ifaddrs>? = first
        while let current = pointer {
            defer { pointer = current.pointee.ifa_next }
            guard let sockaddr = current.pointee.ifa_addr,
                  let address = ipv4(of: sockaddr) else { continue }
            let name = String(cString: current.pointee.ifa_name)
            var prefix = 32
            if let netmask = current.pointee.ifa_netmask,
               let mask = ipv4Bytes(of: netmask) {
                prefix = prefixLength(ofNetmask: mask)
            }
            let broadcast = current.pointee.ifa_dstaddr.flatMap { ipv4(of: $0) }
            result.append(NetworkInterface(name: name, address: address, prefix: prefix, broadcast: broadcast))
        }
        return result
    }

    /// Reads sin_addr out of an IPv4 sockaddr. The struct carries len/family/port before
    /// the four address bytes, so the whole sockaddr must never be handed to
    /// `IPv4Address(data:)` (it wants exactly four bytes).
    static func ipv4(of sockaddr: UnsafeMutablePointer<sockaddr>) -> IPv4Address? {
        guard let bytes = ipv4Bytes(of: sockaddr) else { return nil }
        return IPv4Address(data: bytes)
    }

    /// The four sin_addr bytes of an IPv4 sockaddr, network order.
    static func ipv4Bytes(of sockaddr: UnsafeMutablePointer<sockaddr>) -> Data? {
        guard sockaddr.pointee.sa_family == UInt8(AF_INET) else { return nil }
        return sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
            withUnsafeBytes(of: sin.pointee.sin_addr) { Data($0) }
        }
    }

    /// Prefix length of a 4-byte netmask: 255.255.255.0 -> 24, 255.255.128.0 -> 17.
    static func prefixLength(ofNetmask mask: Data) -> Int {
        var prefix = 0
        for byte in mask.prefix(4) {
            if byte == 0xFF {
                prefix += 8
                continue
            }
            var bit: UInt8 = 0x80
            while bit != 0, byte & bit != 0 {
                prefix += 1
                bit >>= 1
            }
            break
        }
        return min(32, max(0, prefix))
    }

    /// The interface a LAN run should scope to: Wi-Fi (en0), never loopback, cellular
    /// (pdp_ip*, carrier CGNAT space), VPN tunnels or other virtual interfaces.
    /// getifaddrs order is arbitrary; ranking happens explicitly.
    public static func primary() -> NetworkInterface? {
        preferred(among: interfaces())
    }

    /// Loopback, cellular, VPN and virtual interfaces never carry the run's scope.
    static let virtualPrefixes = ["lo", "pdp_ip", "utun", "ipsec", "awdl", "llw", "ap", "bridge", "gif", "stf", "anpi"]

    static func preferred(among all: [NetworkInterface]) -> NetworkInterface? {
        let usable = all.filter { network in
            !Self.virtualPrefixes.contains(where: { network.name.hasPrefix($0) })
        }
        return usable.first { $0.name == "en0" }
            ?? usable.first { $0.name.hasPrefix("en") }
            ?? usable.first
    }

    /// Interface name to gateway address, from the kernel route table. Best effort.
    public static func gateways() -> [String: IPv4Address] {
        RouteTable.defaultGateways()
    }

    /// One line for `get_network_context`.
    public static func summary() -> String {
        guard let primary = primary() else { return "no IPv4 interface found; not on a LAN" }
        var lines = ["interface: \(primary.name)",
                     "own_ip: \(primary.address.string)",
                     "subnet: \(primary.cidr.string)"]
        if let gateway = gateways()[primary.name] {
            lines.append("gateway: \(gateway.string)")
        }
        return lines.joined(separator: "\n")
    }
}

/// Reads the kernel route table (NET_RT_DUMP) for IPv4 default gateways per interface.
/// The route headers exist on macOS only; iOS reports no gateway (best effort by design).
enum RouteTable {
    static func defaultGateways() -> [String: IPv4Address] {
        #if os(macOS)
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0]
        var length = 0
        guard sysctl(&mib, 6, nil, &length, nil, 0) == 0, length > 0 else { return [:] }
        var buffer = Data(count: length)
        guard buffer.withUnsafeMutableBytes({ raw in
            sysctl(&mib, 6, raw.baseAddress, &length, nil, 0)
        }) == 0, length > 0 else { return [:] }

        var gateways: [String: IPv4Address] = [:]
        var offset = 0
        while offset + MemoryLayout<rt_msghdr>.size <= length {
            let header: rt_msghdr = buffer.withUnsafeBytes {
                $0.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
            }
            let messageLength = Int(header.rtm_msglen)
            guard messageLength >= MemoryLayout<rt_msghdr>.size, offset + messageLength <= length else { break }
            defer { offset += messageLength }
            guard header.rtm_type == RTM_GET, header.rtm_flags & RTF_GATEWAY != 0,
                  header.rtm_addrs & RTA_DST != 0 else { continue }

            // Walk the sockaddr chain after the header; only gateway and interface matter here.
            var cursor = offset + MemoryLayout<rt_msghdr>.size
            var gateway: IPv4Address?
            var interfaceName: String?
            let flags: [Int32] = [RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK, RTA_IFP]
            for flag in flags {
                guard header.rtm_addrs & flag != 0, cursor + 8 <= offset + messageLength else { continue }
                let saLen = Int(buffer[buffer.startIndex + cursor])
                let family = Int(buffer[buffer.startIndex + cursor + 1])
                if family == AF_INET, flag == RTA_GATEWAY, saLen >= 16 {
                    var octets: [UInt32] = []
                    for i in 4..<8 { octets.append(UInt32(buffer[buffer.startIndex + cursor + i])) }
                    let value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                    gateway = IPv4Address(value)
                }
                if family == AF_LINK, flag == RTA_IFP {
                    // sockaddr_dl: len, family, index, type, nlen, alen, slen, then the name in sdl_data.
                    let nlen = Int(buffer[buffer.startIndex + cursor + 4])
                    let nameLength = min(nlen, max(0, saLen - 8))
                    if nameLength > 0 {
                        let start = buffer.startIndex + cursor + 8
                        interfaceName = String(decoding: buffer[start..<(start + nameLength)], as: UTF8.self)
                    }
                }
                cursor += (max(saLen, 4) + 3) & ~3
            }
            if let gateway, let interfaceName { gateways[interfaceName] = gateway }
        }
        return gateways
        #else
        return [:]
        #endif
    }
}
