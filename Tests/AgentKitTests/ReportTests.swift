import XCTest
import NeroKit
@testable import AgentKit

final class ReportTests: XCTestCase {
    func testMarkdownCarriesEverythingButNoSecrets() {
        let scope = ScopePolicy(cidrs: [IPv4CIDR("10.0.0.0/24")!], ports: [22, 80],
                                window: TimeWindow(start: Date(timeIntervalSinceNow: -3600), end: Date()),
                                note: "client X floor 3")
        var records: [AuditRecord] = []
        records.append(AuditRecord(tool: "discover_hosts", summary: "Discover live hosts in 10.0.0.0/24",
                                   risk: .medium, decision: .yolo, succeeded: true, detail: ""))
        records.append(AuditRecord(tool: "grab_banner", summary: "Grab the service banner from 10.0.0.5:21",
                                   risk: .medium, decision: .denied, succeeded: false, detail: "denied by operator"))
        let findings = [
            Finding(severity: .high, host: "10.0.0.5", port: 21, module: "ftp_anonymous",
                    title: "anonymous FTP login accepted", detail: "230 after USER anonymous",
                    recommendation: "disable anonymous access",
                    evidence: "USER anonymous\nPASS nero@example.com\n230-"),
        ]
        let loot = [
            LootEntry(id: "L1", kind: "credential", source: "banner 10.0.0.5:21", value: "admin:hunter2!"),
        ]
        let report = RunReport(title: "Client X", operatorNote: "authorized, floor 3", scope: scope,
                               records: records, findings: findings, lootIndex: loot)
        let markdown = report.markdown()

        XCTAssertTrue(markdown.contains("# Client X"))
        XCTAssertTrue(markdown.contains("authorized, floor 3"))
        XCTAssertTrue(markdown.contains("10.0.0.0/24"))
        XCTAssertTrue(markdown.contains("anonymous FTP login accepted"))
        XCTAssertTrue(markdown.contains("disable anonymous access"))
        XCTAssertTrue(markdown.contains("| discover_hosts | medium | yolo | ok |"))
        XCTAssertTrue(markdown.contains("L1 [credential]"))
        // The loot value never appears; the evidence is truncated to 300 characters.
        XCTAssertFalse(markdown.contains("hunter2"))
        XCTAssertTrue(markdown.count < 8_000)

        let json = report.json()
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            let decoded = try decoder.decode(ReportDecodable.self, from: json)
            XCTAssertEqual(decoded.findings.count, 1)
            XCTAssertEqual(decoded.loot.first?.kind, "credential")
        } catch {
            XCTFail("report json must decode: \(error)")
        }
        XCTAssertFalse(json.window.contains("hunter2"))
    }

    struct ReportDecodable: Decodable {
        var title: String
        var hosts: String
        var findings: [Finding]
        var loot: [LootIndex]
        struct LootIndex: Decodable {
            var id: String
            var kind: String
        }
    }
}

private extension Data {
    var window: String { String(decoding: self, as: UTF8.self) }
}
