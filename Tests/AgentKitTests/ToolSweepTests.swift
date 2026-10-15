import XCTest
import NeroKit
@testable import AgentKit

/// Runs every tool the agent has, once, through the real executor against a fake network.
/// A new tool without a sample here fails `testEveryToolHasASample`, so nothing ships untested.
final class ToolSweepTests: XCTestCase {
    /// One valid call per tool, in an order that works against one shared fake network.
    static let samples: [(name: String, args: String)] = [
        ("get_network_context", "{}"),
        ("browse_bonjour", "{}"),
        ("dns_lookup", #"{"host":"192.168.1.1","type":"PTR"}"#),
        ("discover_hosts", #"{"cidr":"192.168.1.0/24"}"#),
        ("scan_ports", #"{"host":"192.168.1.10","ports":[22,80]}"#),
        ("grab_banner", #"{"host":"192.168.1.10","port":80}"#),
        ("http_request", #"{"method":"GET","url":"http://192.168.1.10/admin"}"#),
        ("record_finding", #"{"severity":"high","host":"192.168.1.10","port":6379,"module":"manual","title":"open redis","detail":"answers PING","recommendation":"requirepass"}"#),
        ("get_findings", "{}"),
        ("export_report", #"{"note":"sweep done"}"#),
        ("get_audit_log", #"{"limit":5}"#),
        ("get_app_settings", "{}"),
        ("list_models", "{}"),
        ("test_model_connection", "{}"),
        ("set_scope", #"{"deny_hosts":["192.168.1.66"]}"#),
        ("set_yolo_mode", #"{"enabled":false}"#),
        ("set_auto_approve_medium", #"{"enabled":false}"#),
        ("set_yolo_asks_after_untrusted", #"{"enabled":true}"#),
        ("set_engagement", #"{"enabled":true,"exploit":true,"note":"sweep"}"#),
        ("exploit_check", #"{"module":"redis_unauth","host":"192.168.1.10"}"#),
        ("exploit_run", #"{"module":"redis_unauth","host":"192.168.1.10"}"#),
        ("auth_spray", #"{"service":"redis","host":"192.168.1.10"}"#),
        ("set_engagement", #"{"enabled":false}"#),
    ]

    override func tearDown() { super.tearDown() }

    private func scope() -> ScopePolicy {
        ScopePolicy.localSubnet(IPv4CIDR("192.168.1.0/24")!)
    }

    private func probe() -> FakeProbe {
        let probe = FakeProbe()
        let host = IPv4Address("192.168.1.10")!
        let gateway = IPv4Address("192.168.1.1")!
        probe.seedPing(host: host)
        probe.seed(host: host, port: 22)
        probe.seed(host: host, port: 80)
        probe.seed(host: host, port: 6379)
        probe.seedBanner(host: host, port: 80, "HTTP/1.1 200 OK\nServer: nginx/1.24.0\n\n")
        // Redis: PING answers +PONG, INFO server answers once, AUTH redis (the first bundle
        // password) is accepted, so the spray stops after one attempt.
        probe.seedExchange(host: host, port: 6379, ["+PONG\r\n", "<# Server\r\nredis_version:7.2.0\r\n", "+OK\r\n"])
        probe.seedBanner(host: gateway, port: 80, "")
        probe.seedHTTP(host: "192.168.1.10", port: 80, path: "/admin",
                       HTTPResponse(status: 401, headers: ["www-authenticate": "Basic"], body: Data()))
        probe.seedDNS(name: "1.1.168.192.in-addr.arpa",
                      [DNSRecord(name: "1.1.168.192.in-addr.arpa", rrtype: DNSRecord.ptr, data: Data("gateway".utf8))])
        probe.seedBonjour([BonjourService(name: "Living Room", type: "_airplay._tcp", domain: "local",
                                          port: 7000, txt: ["deviceid=AA:BB", "flags=0x4"])])
        return probe
    }

    /// Thread-safe stand-ins for the app's boxes, mirroring the app wiring.
    final class Boxes: @unchecked Sendable {
        let scopeBox = ScopeBox()
        let policy = PolicyBox()
        var engagement: EngagementState {
            get { policy.snapshot.engagement }
            set { policy.set(yolo: policy.snapshot.yolo, asksAfterUntrusted: policy.snapshot.asksAfterUntrusted, engagement: newValue) }
        }
    }

    private func executor(probe: FakeProbe, gate: ScriptedGate, audit: AuditSink,
                          controls: FakeAppControls, boxes: Boxes, foreground: Bool = true,
                          reportDirectory: URL, vault: LootVault? = nil) -> ToolExecutor {
        ToolExecutor(
            probe: probe, findings: FindingStore(), loot: LootStore(), audit: audit,
            gate: gate, controls: controls,
            settings: { [boxes] in
                let flags = boxes.policy.snapshot
                return ApprovalSettings(autoApproveMedium: false, yolo: flags.yolo,
                                        yoloAsksAfterUntrusted: flags.asksAfterUntrusted,
                                        engagement: flags.engagement)
            },
            scope: { [boxes] in boxes.scopeBox.current },
            onScopeChanged: { [boxes] policy in boxes.scopeBox.set(policy) },
            isForeground: { foreground },
            reportDirectory: reportDirectory,
            reportTitle: { "sweep" },
            vault: vault)
    }

    func testEveryToolHasASample() {
        let specced = Set(ToolCatalog.specs.map(\.name))
        let sampled = Set(Self.samples.map(\.name))
        XCTAssertEqual(specced.subtracting(sampled), [], "tools without a sample in ToolSweepTests")
        XCTAssertEqual(sampled.subtracting(specced), [], "samples for tools that do not exist")
        // set_engagement_mode is sampled twice on purpose: arming first, disarming last.
        let counts = Dictionary(grouping: Self.samples.map(\.name), by: { $0 }).mapValues(\.count)
        XCTAssertEqual(counts.filter { $0.value > 1 }, ["set_engagement": 2], "only the engagement pair may repeat")
    }

    func testEverySampleParsesWithASummaryAndARisk() throws {
        for sample in Self.samples {
            let invocation = try ToolInvocation(name: sample.name, arguments: sample.args)
            XCTAssertEqual(invocation.toolName, sample.name)
            XCTAssertFalse(invocation.summary.isEmpty, sample.name)
            let risk = RiskAssessor.assess(invocation)
            XCTAssertNotEqual(risk.level, .blocked, sample.name)
            XCTAssertFalse(risk.reasons.isEmpty, "\(sample.name) needs a reason the operator can read")
        }
    }

    func testEveryToolRunsAndIsAudited() async throws {
        let probe = probe()
        let audit = InMemoryAuditLog()
        let controls = FakeAppControls()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        let reports = FileManager.default.temporaryDirectory.appending(path: "sweep-\(UUID().uuidString)")
        let ex = executor(probe: probe, gate: ScriptedGate(answer: true), audit: audit, controls: controls,
                          boxes: boxes, reportDirectory: reports)

        for sample in Self.samples {
            let result = await ex.execute(ToolCall(id: sample.name, name: sample.name, arguments: sample.args))
            XCTAssertEqual(result.kind, .ok, "\(sample.name): \(result.content)")
            // The app applies engagement through the controls bridge; mirror that here.
            boxes.engagement = controls.engagement
        }

        let records = await audit.recent(limit: 100)
        XCTAssertEqual(records.map(\.tool), Self.samples.map(\.name))
        XCTAssertTrue(records.allSatisfy(\.succeeded))

        // The exploit checks ran only after the capability was armed by the sample before them.
        let contacted = probe.contacted()
        XCTAssertTrue(contacted.contains { $0.contains("192.168.1.10:6379") })
        XCTAssertTrue(contacted.contains("http 192.168.1.10:80/admin"))
        XCTAssertTrue(contacted.contains { $0.hasPrefix("bonjour") })

        // The report was written into the app container and carries the finding.
        let files = (try? FileManager.default.contentsOfDirectory(at: reports, includingPropertiesForKeys: nil)) ?? []
        XCTAssertEqual(files.filter { $0.pathExtension == "md" }.count, 1)
        let markdown = try String(contentsOf: files.first { $0.pathExtension == "md" }!, encoding: .utf8)
        XCTAssertTrue(markdown.contains("open redis"))
        XCTAssertTrue(markdown.contains("## Timeline"))
    }

    /// The core proof: denied calls and out-of-scope calls change nothing on the wire.
    func testDeniedAndOutOfScopeChangeNothing() async {
        let probe = probe()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        let audit = InMemoryAuditLog()
        let ex = executor(probe: probe, gate: ScriptedGate(answer: false), audit: audit,
                          controls: FakeAppControls(), boxes: boxes,
                          reportDirectory: FileManager.default.temporaryDirectory)
        let before = probe.contacted()

        // Every wire-touching tool is medium or high: each one asks, each one is denied.
        let wireSamples: [(name: String, args: String)] = [
            ("discover_hosts", #"{"cidr":"192.168.1.0/24"}"#),
            ("scan_ports", #"{"host":"192.168.1.10","ports":[22,80]}"#),
            ("grab_banner", #"{"host":"192.168.1.10","port":80}"#),
            ("http_request", #"{"method":"GET","url":"http://192.168.1.10/admin"}"#),
            ("exploit_check", #"{"module":"redis_unauth","host":"192.168.1.10"}"#),
            ("exploit_run", #"{"module":"redis_unauth","host":"192.168.1.10"}"#),
            ("auth_spray", #"{"service":"redis","host":"192.168.1.10"}"#),
        ]
        for sample in wireSamples {
            let result = await ex.execute(ToolCall(id: sample.name, name: sample.name, arguments: sample.args))
            // The exploit trio is capability-blocked before it would even ask; both
            // outcomes prove the same thing: nothing ran.
            XCTAssertTrue(result.kind == .denied || result.kind == .blocked,
                          "\(sample.name): \(result.content)")
        }
        let records = await audit.recent(limit: 100)
        XCTAssertEqual(records.filter { $0.decision == .denied || $0.decision == .blocked }.count, wireSamples.count)

        // Out-of-scope calls are blocked without touching the network at all.
        boxes.scopeBox.set(scope())
        for (name, args) in [
            ("scan_ports", #"{"host":"10.9.9.9","ports":[80]}"#),
            ("grab_banner", #"{"host":"169.254.169.254","port":80}"#),
            ("discover_hosts", #"{"cidr":"10.0.0.0/20"}"#),
            ("http_request", #"{"method":"GET","url":"http://192.168.2.1/"}"#),
        ] {
            let result = await ex.execute(ToolCall(id: name, name: name, arguments: args))
            XCTAssertEqual(result.kind, .blocked, "\(name): \(result.content)")
        }
        XCTAssertEqual(probe.contacted().count, before.count,
                       "denied and out-of-scope calls must not touch the wire")
    }

    func testBlockedLevelsStayBlockedUnderYoloAndEngagement() async {
        let probe = probe()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        boxes.policy.set(yolo: true, asksAfterUntrusted: false,
                         engagement: EngagementState(active: true,
                                                     profile: EngagementProfile(capabilities: Capabilities())))
        let audit = InMemoryAuditLog()
        let ex = executor(probe: probe, gate: ScriptedGate(answer: true), audit: audit,
                          controls: FakeAppControls(), boxes: boxes,
                          reportDirectory: FileManager.default.temporaryDirectory)

        // Capability not armed: exploit tools refuse even under YOLO.
        let result = await ex.execute(ToolCall(id: "c1", name: "exploit_check",
                                               arguments: #"{"module":"redis_unauth","host":"192.168.1.10"}"#))
        XCTAssertEqual(result.kind, .blocked, result.content)

        // An out-of-scope call under YOLO and engagement is still blocked.
        let outside = await ex.execute(ToolCall(id: "c2", name: "scan_ports",
                                                arguments: #"{"host":"8.8.8.8","ports":[53]}"#))
        XCTAssertEqual(outside.kind, .blocked, outside.content)
    }

    func testPermissionChangeSkipsInTheBackground() async {
        let probe = probe()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        boxes.policy.set(yolo: true, asksAfterUntrusted: false, engagement: .inactive)
        let audit = InMemoryAuditLog()
        let ex = executor(probe: probe, gate: ScriptedGate(answer: true), audit: audit,
                          controls: FakeAppControls(), boxes: boxes, foreground: false,
                          reportDirectory: FileManager.default.temporaryDirectory)
        let result = await ex.execute(ToolCall(id: "c1", name: "set_engagement",
                                               arguments: #"{"enabled":true,"exploit":true}"#))
        XCTAssertEqual(result.kind, .error, result.content)
        let records = await audit.recent(limit: 10)
        XCTAssertEqual(records.last?.decision, .skippedNeedsForeground)
    }

    func testScopeChangeViaToolUpdatesTheGuard() async throws {
        let probe = probe()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        let audit = InMemoryAuditLog()
        let ex = executor(probe: probe, gate: ScriptedGate(answer: true), audit: audit,
                          controls: FakeAppControls(), boxes: boxes,
                          reportDirectory: FileManager.default.temporaryDirectory)

        // The deny list lands in the box through onScopeChanged.
        let result = await ex.execute(ToolCall(id: "c1", name: "set_scope",
                                               arguments: #"{"deny_hosts":["192.168.1.10"]}"#))
        XCTAssertEqual(result.kind, .ok, result.content)
        let denied = await ex.execute(ToolCall(id: "c2", name: "grab_banner",
                                               arguments: #"{"host":"192.168.1.10","port":80}"#))
        XCTAssertEqual(denied.kind, .blocked, denied.content)
        XCTAssertTrue(denied.content.contains("denylist"))
    }

    /// Loot values reach the vault only through an approval the operator saw them in:
    /// approval persists, denial does not.
    func testLootPersistsOnlyThroughApproval() async {
        let host = IPv4Address("192.168.1.10")!
        let vault = FakeVault()

        // Approved path: a banner with a secret creates loot; the next approval persists it.
        let probe = FakeProbe()
        probe.seed(host: host, port: 22)
        probe.seedBanner(host: host, port: 22, "password=hunter2secret\r\n")
        probe.seed(host: host, port: 80)
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        let approveGate = ScriptedGate(answer: true)
        let ex = executor(probe: probe, gate: approveGate, audit: InMemoryAuditLog(),
                          controls: FakeAppControls(), boxes: boxes,
                          reportDirectory: FileManager.default.temporaryDirectory, vault: vault)
        let banner = await ex.execute(ToolCall(id: "b", name: "grab_banner",
                                               arguments: #"{"host":"192.168.1.10","port":22}"#))
        XCTAssertEqual(banner.kind, .ok)
        XCTAssertTrue(banner.content.contains("[loot:L1]"), banner.content)
        XCTAssertTrue(vault.persisted.isEmpty, "the read itself must not persist anything")
        let scan = await ex.execute(ToolCall(id: "s", name: "scan_ports",
                                             arguments: #"{"host":"192.168.1.10","ports":[22]}"#))
        XCTAssertEqual(scan.kind, .ok)
        XCTAssertEqual(vault.persisted.map(\.id), ["L1"], "the approval that showed L1 persists it")
        XCTAssertEqual(approveGate.requests.last?.lootPreviews.map(\.id), ["L1"])

        // Denied path: fresh loot stays out of the vault when the approval is denied.
        let denyProbe = FakeProbe()
        denyProbe.seedBanner(host: host, port: 22, "token=denied-token-value\r\n")
        let denyBoxes = Boxes()
        denyBoxes.scopeBox.set(scope())
        let deniedEx = executor(probe: denyProbe, gate: ScriptedGate(answer: false), audit: InMemoryAuditLog(),
                                controls: FakeAppControls(), boxes: denyBoxes,
                                reportDirectory: FileManager.default.temporaryDirectory, vault: vault)
        _ = await deniedEx.execute(ToolCall(id: "b2", name: "grab_banner",
                                            arguments: #"{"host":"192.168.1.10","port":22}"#))
        let deniedScan = await deniedEx.execute(ToolCall(id: "s2", name: "scan_ports",
                                                         arguments: #"{"host":"192.168.1.10","ports":[22]}"#))
        XCTAssertEqual(deniedScan.kind, .denied)
        XCTAssertEqual(vault.persisted.map(\.id), ["L1"], "a denied approval must not persist loot")
    }

    /// A run whose model narrates its plan instead of calling tools gets nudged back to
    /// work instead of silently ending the run (the "it said it would scan and then
    /// nothing happened" case from the audit log).
    func testRunNudgesNarrationBackToTools() async throws {
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        boxes.policy.set(yolo: true, asksAfterUntrusted: false, engagement: .inactive)
        let reports = FileManager.default.temporaryDirectory.appending(path: "nudge-\(UUID().uuidString)")
        let ex = executor(probe: FakeProbe(), gate: ScriptedGate(answer: true), audit: InMemoryAuditLog(),
                          controls: FakeAppControls(), boxes: boxes, reportDirectory: reports)
        final class Collector: @unchecked Sendable {
            private let lock = NSLock()
            private var _texts: [String] = []
            var texts: [String] { lock.withLock { _texts } }
            func add(_ text: String) { lock.withLock { _texts.append(text) } }
        }
        let texts = Collector()
        let llm = ScriptedLLM([
            ChatMessage(role: .assistant, content: "I will now do banner scans."),  // narration, no tools
            toolCall("export_report", #"{"note":"nudged"}"#),
            ChatMessage(role: .assistant, content: "Report written."),
        ])
        let session = AgentSession(llm: llm, executor: ex, scope: boxes.scopeBox.current,
                                   engagement: .inactive, runTitle: "Nudge LAN", isRun: true)
        await session.setMaxSteps(6)
        let answer = try await session.send("Start the run.") { event in
            if case .assistantText(let text) = event { texts.add(text) }
        }
        XCTAssertEqual(answer, "Report written.")
        // The narration became visible immediately instead of vanishing into history.
        XCTAssertEqual(texts.texts.first, "I will now do banner scans.")
        // The second model call saw the nudge as the next user message.
        let second = llm.seenMessages[1]
        XCTAssertTrue(second.contains { $0.role == .user && $0.content?.contains("Do not describe") == true },
                      "the nudge must reach the model")
        let files = (try? FileManager.default.contentsOfDirectory(at: reports, includingPropertiesForKeys: nil)) ?? []
        XCTAssertFalse(files.isEmpty, "the nudged run still exported its report")
    }

    /// A scripted run: context, discover, finding, report. Proves the loop drives the
    /// harness end to end and the audit records the decisions.
    func testScriptedRunWritesFindingsAndReport() async throws {
        let probe = probe()
        let boxes = Boxes()
        boxes.scopeBox.set(scope())
        boxes.policy.set(yolo: true, asksAfterUntrusted: false, engagement: .inactive)
        let audit = InMemoryAuditLog()
        let reports = FileManager.default.temporaryDirectory.appending(path: "run-\(UUID().uuidString)")
        let ex = executor(probe: probe, gate: ScriptedGate(answer: true), audit: audit,
                          controls: FakeAppControls(), boxes: boxes, reportDirectory: reports)
        let llm = ScriptedLLM([
            toolCall("get_network_context"),
            toolCall("discover_hosts", #"{"cidr":"192.168.1.0/24"}"#),
            toolCall("record_finding",
                     #"{"severity":"medium","host":"192.168.1.10","port":22,"module":"manual","title":"ssh reachable","detail":"banner seen"}"#),
            toolCall("export_report"),
            ChatMessage(role: .assistant, content: "Report is written."),
        ])
        let session = AgentSession(llm: llm, executor: ex, scope: boxes.scopeBox.current,
                                   engagement: .inactive, runTitle: "Test LAN", isRun: true)
        await session.setMaxSteps(6)
        let answer = try await session.send("Start the run.")
        XCTAssertTrue(answer.contains("Report is written"))

        let records = await audit.recent(limit: 50)
        XCTAssertTrue(records.contains { $0.tool == "discover_hosts" && $0.decision == .yolo })
        XCTAssertTrue(records.contains { $0.tool == "export_report" })
        let files = (try? FileManager.default.contentsOfDirectory(at: reports, includingPropertiesForKeys: nil)) ?? []
        XCTAssertGreaterThanOrEqual(files.count, 2, "markdown and json report expected")
    }
}
