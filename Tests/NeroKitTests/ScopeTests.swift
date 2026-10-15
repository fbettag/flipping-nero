import XCTest
@testable import NeroKit

final class ScopeTests: XCTestCase {
    // MARK: addresses and blocks

    func testAddressParsing() {
        XCTAssertEqual(IPv4Address("10.0.0.7")?.string, "10.0.0.7")
        XCTAssertEqual(IPv4Address("10.0.0.7")?.value, 0x0A000007)
        XCTAssertNil(IPv4Address("10.0.0"))
        XCTAssertNil(IPv4Address("10.0.0.256"))
        XCTAssertNil(IPv4Address("10.0.0.-1"))
        XCTAssertNil(IPv4Address("010.0.0.1234"))
        XCTAssertNil(IPv4Address("10.0.0.7 "))
        XCTAssertGreaterThan(IPv4Address("10.0.0.2")!, IPv4Address("10.0.0.1")!)
    }

    func testCIDRNormalizationAndContainment() {
        let cidr = IPv4CIDR("192.168.1.77/24")!
        XCTAssertEqual(cidr.string, "192.168.1.0/24")
        XCTAssertTrue(cidr.contains(IPv4Address("192.168.1.254")!))
        XCTAssertFalse(cidr.contains(IPv4Address("192.168.2.1")!))
        XCTAssertEqual(cidr.hostCount, 256) // total addresses; hosts excludes network and broadcast
        XCTAssertEqual(cidr.broadcast.string, "192.168.1.255")
        XCTAssertEqual(cidr.hosts.count, 254)
        XCTAssertEqual(cidr.hosts.first?.string, "192.168.1.1")
        XCTAssertEqual(cidr.hosts.last?.string, "192.168.1.254")
    }

    /// A `/8` is not a valid scope argument: the parser refuses anything wider than /20.
    func testCIDRRefusesWideBlocks() {
        XCTAssertNil(IPv4CIDR("10.0.0.0/8"))
        XCTAssertNil(IPv4CIDR("10.0.0.0/16"))
        XCTAssertNil(IPv4CIDR("10.0.0.0/19"))
        XCTAssertNotNil(IPv4CIDR("10.0.0.0/20"))
        XCTAssertNil(IPv4CIDR("10.0.0.0/33"))
        XCTAssertNil(IPv4CIDR("10.0.0.0"))
    }

    // MARK: the guard

    private func policy(cidrs: [String] = ["192.168.1.0/24"], deny: Set<IPv4Address> = [],
                        ports: Set<UInt16> = [22, 80], window: TimeWindow? = nil,
                        capabilities: Capabilities = Capabilities()) -> ScopePolicy {
        ScopePolicy(cidrs: cidrs.map { IPv4CIDR($0) }.compactMap { $0 }, denyHosts: deny, ports: ports,
                    window: window, capabilities: capabilities)
    }

    func testWithoutScopeEverythingIsBlocked() {
        let verdict = ScopeGuard.check([.host(IPv4Address("192.168.1.1")!)], policy: nil)
        XCTAssertEqual(verdict, .blocked("no scope is set; start a run or set one with set_scope"))
    }

    func testInScopeHostAndPortsPass() {
        let scope = policy()
        XCTAssertEqual(ScopeGuard.check([.host(IPv4Address("192.168.1.10")!), .port(80)], policy: scope), .ok)
    }

    func testOutsideAllowlistIsBlocked() {
        let scope = policy()
        guard case .blocked = ScopeGuard.check([.host(IPv4Address("10.0.0.1")!)], policy: scope) else {
            return XCTFail("outside the allowlist must be blocked")
        }
        guard case .blocked = ScopeGuard.check([.hosts(IPv4CIDR("10.0.0.0/24")!, count: 254)], policy: scope) else {
            return XCTFail("a foreign block must be blocked")
        }
    }

    func testDenylistWins() {
        let scope = policy(deny: [IPv4Address("192.168.1.12")!])
        guard case .blocked = ScopeGuard.check([.host(IPv4Address("192.168.1.12")!)], policy: scope) else {
            return XCTFail("denylist host must be blocked")
        }
    }

    func testPortAllowlist() {
        let scope = policy()
        guard case .blocked = ScopeGuard.check([.host(IPv4Address("192.168.1.10")!), .port(8080)], policy: scope) else {
            return XCTFail("port outside the allowlist must be blocked")
        }
        guard case .blocked = ScopeGuard.check([.host(IPv4Address("192.168.1.10")!), .ports([22, 80, 8443])], policy: scope) else {
            return XCTFail("one bad port blocks the whole list")
        }
    }

    func testCapsLimitCallSize() {
        let scope = policy()
        guard case .blocked(let why) = ScopeGuard.check([.hosts(IPv4CIDR("192.168.1.0/21")!, count: 1000)], policy: scope) else {
            return XCTFail("oversized block must be blocked")
        }
        XCTAssertTrue(why.contains("cap"), why)
    }

    func testTimeWindow() {
        let scope = policy(window: TimeWindow(start: Date().addingTimeInterval(-60), end: Date().addingTimeInterval(-1)))
        guard case .blocked(let why) = ScopeGuard.check([.port(80)], policy: scope) else {
            return XCTFail("expired window must block")
        }
        XCTAssertTrue(why.contains("expired"), why)
    }

    func testNeverAllowedRanges() {
        let scope = policy(cidrs: ["0.0.0.0/0"])
        for bad in ["127.0.0.1", "224.0.0.1", "240.0.0.1", "0.0.0.1"] {
            guard case .blocked = ScopeGuard.check([.host(IPv4Address(bad)!)], policy: scope) else {
                return XCTFail("\(bad) must never be in scope")
            }
        }
        // A sweep block may not overlap a never-allowed range either.
        guard case .blocked = ScopeGuard.check([.hosts(IPv4CIDR("224.0.0.0/20")!, count: 10)], policy: policy()) else {
            return XCTFail("block overlapping multicast must be rejected")
        }
    }

    func testLinkLocalIsBlockedUntilCloudReadonly() {
        let plain = policy()
        guard case .blocked(let why) = ScopeGuard.check([.host(IPv4Address("169.254.169.254")!)], policy: plain) else {
            return XCTFail("link-local must be blocked")
        }
        XCTAssertTrue(why.contains("cloud_readonly"), why)
        guard case .blocked = ScopeGuard.check([.hosts(IPv4CIDR("169.254.1.0/24")!, count: 254)], policy: policy(capabilities: Capabilities(cloudReadonly: true))) else {
            return XCTFail("link-local sweep blocks stay blocked even with the capability")
        }
        let armed = policy(capabilities: Capabilities(cloudReadonly: true))
        XCTAssertEqual(ScopeGuard.check([.host(IPv4Address("169.254.169.254")!)], policy: armed), .ok)
    }

    // MARK: loosening detection for set_scope

    func testIsLoosening() {
        let current = policy(deny: [IPv4Address("192.168.1.66")!], ports: [22, 80])
        // Same or tighter passes.
        XCTAssertFalse(current.isLoosening(policy(deny: [IPv4Address("192.168.1.66")!, IPv4Address("192.168.1.67")!], ports: [22])))
        XCTAssertFalse(current.isLoosening(current))
        // Wider network, removed deny, added port, longer window: all loosening.
        XCTAssertTrue(current.isLoosening(policy(cidrs: ["192.168.0.0/20"], ports: [22, 80])))
        XCTAssertTrue(current.isLoosening(policy(ports: [22, 80])))
        XCTAssertTrue(current.isLoosening(ScopePolicy(cidrs: current.cidrs, ports: current.ports,
                                                      window: TimeWindow(start: .now, end: .now.addingTimeInterval(99_000)))))
    }

    // MARK: sanitizer and loot

    func testSanitizer() {
        XCTAssertEqual(TextSanitizer.clean("a\u{00}b\u{1B}[31m"), "ab[31m")
        XCTAssertTrue(TextSanitizer.clean(String(repeating: "x", count: 100), maxLength: 10).hasSuffix("[truncated]"))
        XCTAssertFalse(TextSanitizer.sanitizeName("line1\nline2").contains("\n"))
    }

    /// Netmask-to-prefix parsing; a wrong byte offset here once made every interface
    /// invisible on a real phone ("no subnet found").
    func testNetmaskPrefixParsing() {
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([255, 255, 255, 0])), 24)
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([255, 255, 255, 252])), 30)
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([255, 255, 0, 0])), 16)
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([255, 255, 128, 0])), 17)
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([255, 255, 255, 255])), 32)
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data([0, 0, 0, 0])), 0)
        // Never more than 32, whatever garbage comes in.
        XCTAssertEqual(NetworkContext.prefixLength(ofNetmask: Data(repeating: 255, count: 8)), 32)
    }

    /// The interfaces call itself must find the primary IPv4 interface on this machine
    /// (the test host has at least loopback; macOS adds a real en0).
    func testPrimaryInterfaceIsUsableForScope() throws {
        let primary = try XCTUnwrap(NetworkContext.primary(),
                                    "a machine running tests has a non-loopback IPv4 interface")
        XCTAssertGreaterThanOrEqual(primary.prefix, 0)
        XCTAssertLessThanOrEqual(primary.prefix, 32)
        XCTAssertFalse(primary.name.hasPrefix("lo"))
        XCTAssertFalse(primary.name.hasPrefix("utun"))
        _ = primary.cidr // must not crash on any prefix
    }

    /// Wi-Fi wins over cellular: getifaddrs on an iPhone hands out pdp_ip0 (carrier
    /// CGNAT space) before en0, and a run must never scope to it.
    func testPrimaryPrefersWiFiOverCellular() {
        let wifi = NetworkInterface(name: "en0", address: IPv4Address("192.168.178.42")!, prefix: 24, broadcast: nil)
        let cellular = NetworkInterface(name: "pdp_ip0", address: IPv4Address("10.188.99.180")!, prefix: 28, broadcast: nil)
        let loopback = NetworkInterface(name: "lo0", address: IPv4Address("127.0.0.1")!, prefix: 8, broadcast: nil)
        // Whatever order the kernel reports, Wi-Fi is picked.
        XCTAssertEqual(NetworkContext.preferred(among: [loopback, cellular, wifi]), wifi)
        XCTAssertEqual(NetworkContext.preferred(among: [wifi, cellular, loopback]), wifi)
        // Without Wi-Fi nothing is chosen: cellular is never a LAN scope.
        XCTAssertNil(NetworkContext.preferred(among: [loopback, cellular]))
        // Other ethernet-style names (simulator, VM, adapter) still work.
        let other = NetworkInterface(name: "en1", address: IPv4Address("10.1.2.3")!, prefix: 24, broadcast: nil)
        XCTAssertEqual(NetworkContext.preferred(among: [loopback, other]), other)
    }

    func testLootExtractionAndRedaction() async {
        let secret = "AKIAIOSFODNN7EXAMPLE"
        let text = "aws_id=\(secret) password=hunter2! jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.KolBWzIi_MQ"
        let found = LootScanner.extract(text)
        XCTAssertTrue(found.contains { $0.kind == "aws_access_key" && $0.value == secret }, "\(found)")
        XCTAssertTrue(found.contains { $0.kind == "credential" && $0.value == "hunter2!" }, "\(found)")
        XCTAssertTrue(found.contains { $0.kind == "jwt" }, "\(found)")

        let loot = LootStore()
        let redacted = await LootScanner.redact(text, source: "test", loot: loot)
        XCTAssertFalse(redacted.text.contains(secret))
        XCTAssertTrue(redacted.text.contains("[loot:L1]"))
        XCTAssertEqual(redacted.ids.count, 3, "aws key, credential and jwt each became loot")
        // A second pass over the same value creates no duplicate loot.
        let again = await LootScanner.redact(secret, source: "test", loot: loot)
        XCTAssertTrue(again.ids.isEmpty)
        let index = await loot.index()
        XCTAssertEqual(index.count, 3)
        XCTAssertFalse(index[0].preview.contains(secret))
    }

    func testEvidenceSummaryIsCappedAndNamed() {
        var evidence = Evidence(module: "redis_unauth", host: "10.0.0.5", port: 6379)
        evidence.add(request: "PING\r\n\u{07}bell", response: Data("+PONG\r\n".utf8))
        evidence.add(request: "INFO server", response: Data())
        let summary = evidence.summary
        XCTAssertTrue(summary.contains("redis_unauth 10.0.0.5:6379"))
        XCTAssertTrue(summary.contains("> PING"))
        XCTAssertTrue(summary.contains("< +PONG"))
        XCTAssertTrue(summary.contains("(no answer)"))
        XCTAssertFalse(summary.contains("\u{07}"))
    }

    // MARK: exploit registry

    func testRegistryIsFixedAndNamed() {
        XCTAssertEqual(ExploitRegistry.names,
                       ["ftp_anonymous", "http_unauth_panel", "memcached_unauth", "mqtt_anonymous", "redis_unauth"])
        XCTAssertTrue(ExploitRegistry.list().contains("anonymous"))
    }

    func testParallelKeepsOrder() async {
        let input = Array(0..<50)
        let output = await Parallel.map(input, limit: 8) { value -> Int in
            try? await Task.sleep(for: .milliseconds(UInt64.random(in: 0...2)))
            return value * 2
        }
        XCTAssertEqual(output, input.map { $0 * 2 })
    }
}
