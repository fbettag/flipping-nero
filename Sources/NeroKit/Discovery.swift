import Foundation
import os

/// Common TCP ports for the `top-100` preset, roughly in how often they answer.
public enum PortPreset {
    public static let top100: [UInt16] = [
        80, 443, 22, 445, 139, 3389, 8080, 21, 23, 25, 53, 111, 137, 138, 161, 389, 427, 465, 514,
        515, 548, 554, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1883, 2049, 2181, 2222, 2375, 2376,
        3000, 3128, 3260, 3306, 3388, 3690, 4443, 4444, 5000, 5001, 5060, 5432, 5439, 5601, 5672,
        5900, 5984, 6379, 6443, 6666, 6667, 7000, 7001, 7077, 8000, 8008, 8009, 8081, 8089, 8181,
        8443, 8500, 873, 8888, 9000, 9001, 9042, 9080, 9090, 9092, 9200, 9300, 9418, 9999, 10000,
        102, 109, 110, 113, 119, 123, 135, 179, 264, 280, 366, 407, 444, 513, 540, 543, 544,
        5666, 8082, 8083, 8085,
    ]
}

/// Runs async work with a bounded number of concurrent tasks and keeps input order.
public enum Parallel {
    final class Cursor: @unchecked Sendable {
        private let lock = NSLock()
        private var index = 0
        let count: Int
        init(count: Int) { self.count = count }
        func next() -> Int? {
            lock.lock()
            defer { lock.unlock() }
            guard index < count else { return nil }
            index += 1
            return index - 1
        }
    }

    public static func map<Input: Sendable, Output: Sendable>(_ input: [Input], limit: Int,
                                                              _ body: @escaping @Sendable (Input) async -> Output) async -> [Output] {
        guard !input.isEmpty else { return [] }
        let concurrency = max(1, min(limit, input.count))
        let cursor = Cursor(count: input.count)
        return await withTaskGroup(of: [(Int, Output)].self) { group in
            for _ in 0..<concurrency {
                group.addTask {
                    var results: [(Int, Output)] = []
                    while let index = cursor.next() {
                        results.append((index, await body(input[index])))
                    }
                    return results
                }
            }
            var collected: [(Int, Output)] = []
            while let partial = await group.next() { collected += partial }
            return collected.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }
}

public struct DiscoveryResult: Sendable, Equatable {
    public var alive: [IPv4Address]
    public var swept: Int
}

public struct PortScanResult: Sendable, Equatable {
    public var host: IPv4Address
    public var open: [UInt16]
}

/// Thread-safe counter for progress callbacks out of a task group.
final class ProgressCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() -> Int {
        lock.withLock {
            value += 1
            return value
        }
    }
}

/// Recon engines. They never decide scope themselves: the executor validated every target
/// before calling in, and the engines stay inside exactly what they were handed.
public enum Discovery {
    /// ICMP plus a connect fallback on a few ports, only inside the handed block.
    public static func discoverHosts(cidr: IPv4CIDR, deny: Set<IPv4Address>, ports: Set<UInt16>,
                                     probe: NetworkProbe, caps: ScopeCaps,
                                     onProgress: @escaping @Sendable (Int, Int) -> Void = { _, _ in })
        async -> DiscoveryResult {
        let hosts = cidr.hosts.filter { !deny.contains($0) }
        // Discovery connect ports are the scope allowlist's lowest entries, so nothing
        // outside the port allowlist is ever touched.
        let connectPorts = Array(PortPreset.top100.filter { ports.contains($0) }.prefix(4))
        let timeout = min(.milliseconds(800), caps.maxTimeout)
        let counter = ProgressCounter()

        let alive = await Parallel.map(hosts, limit: caps.maxConcurrency) { host in
            let pinged = await probe.ping(host, timeout: timeout)
            let connected = pinged ? false : await Self.answersConnect(host, ports: connectPorts, probe: probe, timeout: timeout)
            onProgress(counter.increment(), hosts.count)
            return pinged || connected ? host : nil
        }
        let found = alive.compactMap { $0 }
        return DiscoveryResult(alive: found, swept: hosts.count)
    }

    static func answersConnect(_ host: IPv4Address, ports: [UInt16], probe: NetworkProbe,
                               timeout: Duration) async -> Bool {
        for port in ports {
            if await probe.tcpConnect(host, port: port, timeout: timeout) { return true }
        }
        return false
    }

    public static func scanPorts(host: IPv4Address, ports: [UInt16], probe: NetworkProbe, caps: ScopeCaps,
                                 onProgress: @escaping @Sendable (Int, Int) -> Void = { _, _ in })
        async -> PortScanResult {
        let timeout = min(.seconds(1), caps.maxTimeout)
        let counter = ProgressCounter()
        let open = await Parallel.map(ports, limit: caps.maxConcurrency) { port in
            let isOpen = await probe.tcpConnect(host, port: port, timeout: timeout)
            onProgress(counter.increment(), ports.count)
            return isOpen ? port : nil
        }
        return PortScanResult(host: host, open: open.compactMap { $0 }.sorted())
    }

    public static func grabBanner(host: IPv4Address, port: UInt16, probe: NetworkProbe,
                                  caps: ScopeCaps) async -> String? {
        guard let data = await probe.readBanner(host, port: port, timeout: min(.seconds(2), caps.maxTimeout),
                                                maxBytes: caps.maxBannerBytes) else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        return text.isEmpty ? nil : text
    }
}
