import Foundation
import NeroKit

public struct ToolResult: Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case ok, error, denied, blocked }
    public var content: String
    public var kind: Kind
    public var isError: Bool { kind != .ok }
    public static func ok(_ text: String) -> ToolResult { .init(content: text, kind: .ok) }
    public static func error(_ text: String, kind: Kind = .error) -> ToolResult { .init(content: text, kind: kind) }
}

/// App-level settings the agent may read or change through tools.
/// Credentials are reduced to "is one stored"; loosening only ever happens after
/// the executor obtained explicit consent from the operator.
public struct AppSettingsSnapshot: Sendable, Equatable {
    public var yolo: Bool
    public var yoloAsksAfterUntrusted: Bool
    public var autoApproveMedium: Bool
    public var engagementActive: Bool
    public var engagementSummary: String
    public var scopeSummary: String
    public var model: String
    public var provider: String
    public var apiKeyStored: Bool

    public init(yolo: Bool, yoloAsksAfterUntrusted: Bool, autoApproveMedium: Bool,
                engagementActive: Bool, engagementSummary: String, scopeSummary: String,
                model: String, provider: String, apiKeyStored: Bool) {
        self.yolo = yolo
        self.yoloAsksAfterUntrusted = yoloAsksAfterUntrusted
        self.autoApproveMedium = autoApproveMedium
        self.engagementActive = engagementActive
        self.engagementSummary = engagementSummary
        self.scopeSummary = scopeSummary
        self.model = model
        self.provider = provider
        self.apiKeyStored = apiKeyStored
    }
}

public protocol AppControls: Sendable {
    func settings() async -> AppSettingsSnapshot
    func setYolo(_ enabled: Bool) async
    func setAutoApproveMedium(_ enabled: Bool) async
    func setYoloAsksAfterUntrusted(_ enabled: Bool) async
    /// Arming only ever arrives here after the executor obtained explicit consent.
    func setEngagement(_ state: EngagementState) async
    func setModel(_ model: String) async
    func setProvider(_ provider: AIProvider, baseURL: String?) async throws
    func listModels() async throws -> [AIModel]
    func testConnection() async throws
}

/// Where approved loot values go: the Keychain in the app, a recorder in tests.
/// Only entries the operator saw in an approval sheet and approved are persisted;
/// everything else stays in memory for the session.
public protocol LootVault: Sendable {
    func persist(_ entries: [LootEntry]) async
}

/// Runs model tool calls through the harness, always in this order:
/// parse → ScopeGuard → RiskAssessor → Approval → execution → Untrusted.wrap → Audit.
/// Never throws; every failure becomes an error result the model can read.
public actor ToolExecutor {
    private let probe: NetworkProbe
    private let findings: FindingStore
    private let loot: LootStore
    private let audit: AuditSink
    private let gate: ApprovalGate
    private let controls: AppControls?
    private let settings: @Sendable () -> ApprovalSettings
    private let scope: @Sendable () -> ScopePolicy?
    /// Called after an approved `set_scope` so the app can update its scope box and UI.
    private let onScopeChanged: (@Sendable (ScopePolicy) -> Void)?
    /// False while the run is in the background; permission changes then skip instead of asking.
    private let isForeground: @Sendable () -> Bool
    private let reportDirectory: URL
    private let reportTitle: @Sendable () -> String
    /// Approved loot lands here (the Keychain in the app); nil keeps everything in memory.
    private let vault: LootVault?
    /// How an approval is recorded in the audit log: `.approved` in the app, `.shortcut` for Siri.
    private let approvedAs: AuditRecord.Decision
    public nonisolated let nonce: String
    private var tainted = false
    /// Progress callback for discovery and port sweeps, wired to the Live Activity.
    private var progressHandler: (@Sendable (String, Int, Int) -> Void)?
    public func setProgressHandler(_ handler: @escaping @Sendable (String, Int, Int) -> Void) {
        progressHandler = handler
    }

    public init(probe: NetworkProbe, findings: FindingStore, loot: LootStore, audit: AuditSink,
                gate: ApprovalGate, controls: AppControls? = nil,
                settings: @escaping @Sendable () -> ApprovalSettings = { ApprovalSettings() },
                scope: @escaping @Sendable () -> ScopePolicy? = { nil },
                onScopeChanged: (@Sendable (ScopePolicy) -> Void)? = nil,
                isForeground: @escaping @Sendable () -> Bool = { true },
                reportDirectory: URL = FileManager.default.temporaryDirectory,
                reportTitle: @escaping @Sendable () -> String = { "LAN run" },
                vault: LootVault? = nil,
                approvedAs: AuditRecord.Decision = .approved,
                nonce: String = UUID().uuidString.prefix(8).lowercased()) {
        self.probe = probe
        self.findings = findings
        self.loot = loot
        self.audit = audit
        self.gate = gate
        self.controls = controls
        self.settings = settings
        self.scope = scope
        self.onScopeChanged = onScopeChanged
        self.isForeground = isForeground
        self.reportDirectory = reportDirectory
        self.reportTitle = reportTitle
        self.vault = vault
        self.approvedAs = approvedAs
        self.nonce = nonce
    }

    public var isTainted: Bool { tainted }

    /// Call when the operator sends a new message; their words re-establish trust.
    public func newUserTurn() { tainted = false }

    // MARK: the chain

    public func execute(_ call: ToolCall) async -> ToolResult {
        let invocation: ToolInvocation
        do {
            invocation = try ToolInvocation(name: call.name, arguments: call.arguments)
        } catch {
            await audit.record(.init(tool: call.name, summary: "invalid call", risk: nil, decision: .invalid,
                                     succeeded: false, detail: "\(error)"))
            return .error("\(error)")
        }

        let current = settings()
        let assessment = RiskAssessor.assess(invocation)

        // Scope before anything else about the network: without scope, every network tool is blocked.
        let targets = await scopeTargets(invocation)
        if !targets.isEmpty {
            switch ScopeGuard.check(targets, policy: scope()) {
            case .blocked(let why):
                return await refuse(invocation, risk: assessment.level,
                                    why: "out of scope: \(why)")
            case .ok:
                break
            }
        }

        if assessment.level == .blocked {
            return await refuse(invocation, risk: assessment.level,
                                why: "blocked by policy: \(assessment.reasons.joined(separator: "; "))")
        }

        // Capability-gated tools refuse to run until the operator armed engagement.
        if let capability = invocation.armedCapability, !current.engagement.armed(capability) {
            return await refuse(invocation, risk: assessment.level,
                                why: "capability not armed: the operator must arm engagement "
                                    + "(\(current.engagement.active ? "without" : "including") this capability). Stop retrying until then.")
        }

        // Loosening always asks, even under YOLO or an armed engagement.
        let consent = invocation.requiresExplicitConsent || invocation.loosensScope(scope())
        var decision = AuditRecord.Decision.auto
        if consent || ApprovalPolicy.requiresApproval(assessment, settings: current, tainted: tainted) {
            if consent && !isForeground() {
                return await skipForForeground(invocation, risk: assessment.level)
            }
            let previewEntries = Array(await loot.index().suffix(3))
            let previews = previewEntries.map { ApprovalLoot(id: $0.id, kind: $0.kind, preview: $0.preview) }
            let request = ApprovalRequest(
                tool: invocation.toolName, summary: invocation.summary, risk: assessment.level,
                reasons: assessment.reasons, afterUntrustedContent: tainted,
                isPermissionChange: consent, lootPreviews: previews)
            guard await gate.decide(request) else {
                await audit.record(.init(tool: invocation.toolName, summary: invocation.summary, risk: assessment.level,
                                         decision: .denied, succeeded: false, detail: "denied by operator"))
                return .error("The operator denied this action. Do not repeat it; ask what they want instead.", kind: .denied)
            }
            decision = approvedAs
            // The operator saw these values in the sheet and approved: now they may persist.
            if !previewEntries.isEmpty {
                await vault?.persist(previewEntries)
            }
        } else if current.engagement.active, current.engagement.profile.capabilities.autoApprovals, assessment.level >= .medium {
            decision = .engaged
        } else if current.yolo && assessment.level >= .medium {
            decision = .yolo
        }

        do {
            let output = try await run(invocation)
            await audit.record(.init(tool: invocation.toolName, summary: invocation.summary, risk: assessment.level,
                                     decision: decision, succeeded: true, detail: ""))
            return .ok(output)
        } catch {
            await audit.record(.init(tool: invocation.toolName, summary: invocation.summary, risk: assessment.level,
                                     decision: decision, succeeded: false, detail: "\(error)"))
            return .error("\(error)")
        }
    }

    /// Blocked is blocked: the tool never runs, and the audit says why.
    private func refuse(_ invocation: ToolInvocation, risk: RiskLevel, why: String) async -> ToolResult {
        await audit.record(.init(tool: invocation.toolName, summary: invocation.summary, risk: risk,
                                 decision: .blocked, succeeded: false, detail: why))
        return .error("\(why). Do not retry or look for a workaround; tell the operator.", kind: .blocked)
    }

    private func skipForForeground(_ invocation: ToolInvocation, risk: RiskLevel) async -> ToolResult {
        await audit.record(.init(tool: invocation.toolName, summary: invocation.summary, risk: risk,
                                 decision: .skippedNeedsForeground, succeeded: false,
                                 detail: "permission change requested while the app is in the background"))
        return .error("Skipped: loosening permissions needs a dialog in the app. Continue with the next step; "
                    + "the operator can approve it later.", kind: .error)
    }

    // MARK: execution

    private func run(_ invocation: ToolInvocation) async throws -> String {
        switch invocation {
        case .getNetworkContext:
            var lines = [NetworkContext.summary()]
            if let policy = scope() {
                lines.append("scope: \(Self.describe(policy))")
            } else {
                lines.append("scope: none set")
            }
            return lines.joined(separator: "\n")

        case .discoverHosts(let cidr):
            let policy = scope()!
            let progress = progressHandler
            let result = await Discovery.discoverHosts(
                cidr: cidr, deny: policy.denyHosts, ports: policy.ports, probe: probe, caps: policy.caps,
                onProgress: { done, total in progress?("discover", done, total) })
            for host in result.alive { await findings.noteHost(host.string) }
            tainted = true
            let list = result.alive.map(\.string).joined(separator: ", ")
            return Untrusted.wrap("""
            swept \(result.swept) hosts in \(cidr.string): \(result.alive.count) alive
            alive: \(list.isEmpty ? "(none)" : list)
            """, source: "discover \(cidr.string)", nonce: nonce)

        case .scanPorts(let host, let ports):
            let policy = scope()!
            let progress = progressHandler
            let result = await Discovery.scanPorts(
                host: host, ports: ports, probe: probe, caps: policy.caps,
                onProgress: { done, total in progress?("ports", done, total) })
            await findings.noteHost(host.string)
            tainted = true
            return Untrusted.wrap("open on \(host.string): \(result.open.map(String.init).joined(separator: ", ").isEmpty ? "(none)" : result.open.map(String.init).joined(separator: ", "))",
                                  source: "ports \(host.string)", nonce: nonce)

        case .browseBonjour:
            let services = await probe.browseBonjour(BonjourTypes.declared, timeout: .seconds(4))
            tainted = true
            for service in services { await findings.noteHost("bonjour \(service.name)") }
            let text = services.isEmpty ? "(no services advertised)" : services.map(\.summary).joined(separator: "\n")
            return Untrusted.wrap(text, source: "bonjour", nonce: nonce)

        case .grabBanner(let host, let port):
            let policy = scope()!
            guard let banner = await Discovery.grabBanner(host: host, port: port, probe: probe, caps: policy.caps) else {
                await findings.noteHost(host.string)
                return "No banner from \(host.string):\(port) (connected or refused, nothing sent)."
            }
            await findings.noteHost(host.string)
            tainted = true
            let redacted = await LootScanner.redact(banner, source: "banner \(host.string):\(port)", loot: loot)
            return Untrusted.wrap(redacted.text + lootNote(redacted.ids),
                                  source: "banner \(host.string):\(port)", nonce: nonce)

        case .httpRequest(let method, let url, let headers, let body):
            let response = try await probe.http(
                HTTPRequestSpec(method: method, url: url, headers: headers,
                                body: body.map { Data($0.utf8) }),
                timeout: .seconds(5))
            if let host = url.host { await findings.noteHost(host) }
            tainted = true
            var lines = ["HTTP \(response.status) \(url.absoluteString)"]
            for key in ["server", "content-type", "location", "www-authenticate"] {
                if let value = response.headers[key] { lines.append("\(key): \(Untrusted.sanitizeName(value))") }
            }
            let text = await LootScanner.redact(response.text(maxBytes: 1_500),
                                                source: "http \(url.host ?? "")", loot: loot)
            lines.append("")
            lines.append(text.text.isEmpty ? "(empty body)" : text.text)
            return Untrusted.wrap(lines.joined(separator: "\n") + lootNote(text.ids),
                                  source: "http \(url.host ?? "")", nonce: nonce)

        case .dnsLookup(let name, let rrtype):
            tainted = true
            var lines: [String] = []
            if rrtype == DNSRecord.ptr, let address = IPv4Address(name) {
                if let ptr = await DNSResolver.ptr(for: address) { lines.append("PTR \(ptr)") }
            } else {
                if let records = try? await probe.queryDNS(name, rrtype: rrtype, timeout: .seconds(2)) {
                    lines += records.map { "\(ToolInvocation.rrtypeName(rrtype)) \($0.text)" }
                } else {
                    lines.append("(no answer)")
                }
            }
            // Resolved addresses are reported with their scope status, never contacted.
            for address in DNSResolver.addresses(for: name) {
                let inScope = scope().map { ScopeGuard.check([.host(address)], policy: $0) == .ok } ?? false
                lines.append("resolves to \(address.string)\(inScope ? " (in scope)" : " (NOT in scope)")")
            }
            return Untrusted.wrap(lines.joined(separator: "\n"), source: "dns \(name)", nonce: nonce)

        case .recordFinding(let severity, let host, let port, let module, let title,
                            let detail, let recommendation, let evidence):
            if let address = IPv4Address(host) {
                // Validated here: a finding may only name a host the scope could touch.
                if let verdict = ScopeGuard.checkHost(address, policy: scope() ?? ScopePolicy(), explicit: true),
                   case .blocked = verdict {
                    throw ToolError.badArguments("finding host \(host) is outside the scope")
                }
            }
            let finding = Finding(severity: severity, host: Untrusted.sanitizeName(host), port: port,
                                  module: Untrusted.sanitizeName(module),
                                  title: Untrusted.sanitizeName(title),
                                  detail: Untrusted.clean(detail, maxLength: 2_000),
                                  recommendation: Untrusted.sanitizeName(recommendation),
                                  evidence: Untrusted.clean(evidence, maxLength: 2_000))
            await findings.add(finding)
            let count = await findings.counts.findings
            return "Recorded finding #\(count): \(severity.rawValue) \(title) on \(host)\(port.map { ":\($0)" } ?? "")"

        case .getFindings:
            let list = await findings.snapshot()
            tainted = true
            guard !list.isEmpty else { return "No findings recorded yet." }
            let text = list.enumerated().map { index, finding in
                "#\(index + 1) [\(finding.severity.rawValue)] \(finding.host)\(finding.port.map { ":\($0)" } ?? "")"
                    + " (\(finding.module)) \(finding.title)"
                    + (finding.detail.isEmpty ? "" : " — \(finding.detail)")
            }.joined(separator: "\n")
            return Untrusted.wrap(text, source: "findings", nonce: nonce)

        case .exportReport(let note):
            let records = await audit.recent(limit: 500)
            let list = await findings.snapshot()
            let lootIndex = await loot.index()
            let report = RunReport(
                title: reportTitle(), operatorNote: Untrusted.clean(note, maxLength: 500),
                scope: scope(), records: records,
                findings: list, lootIndex: lootIndex)
            try FileManager.default.createDirectory(at: reportDirectory, withIntermediateDirectories: true)
            let markdownURL = reportDirectory
                .appendingPathComponent("\(report.fileNameBase).md")
            let jsonURL = reportDirectory
                .appendingPathComponent("\(report.fileNameBase).json")
            try report.markdown().write(to: markdownURL, atomically: true, encoding: .utf8)
            try report.json().write(to: jsonURL)
            return "Report written: \(markdownURL.lastPathComponent), \(jsonURL.lastPathComponent). "
                + "It is in the app container; the operator shares it from the Findings tab. Nothing was sent to the network."

        case .getAuditLog(let limit):
            let entries = await audit.recent(limit: limit)
            guard !entries.isEmpty else { return "The audit log is empty." }
            tainted = true
            let text = entries.map { record in
                let time = record.date.formatted(date: .abbreviated, time: .shortened)
                return "\(time) \(record.tool) [\(record.decision.rawValue), \(record.succeeded ? "ok" : "failed")] \(Untrusted.sanitizeName(record.summary))"
            }.joined(separator: "\n")
            return Untrusted.wrap(text, source: "audit log", nonce: nonce)

        case .getAppSettings:
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            let snapshot = await controls.settings()
            return """
            yolo_mode: \(snapshot.yolo)
            yolo_asks_after_untrusted: \(snapshot.yoloAsksAfterUntrusted)
            auto_approve_medium: \(snapshot.autoApproveMedium)
            engagement: \(snapshot.engagementActive ? "armed (\(snapshot.engagementSummary))" : "off")
            scope: \(snapshot.scopeSummary)
            model: \(snapshot.model)
            ai_provider: \(snapshot.provider)
            api_key_stored: \(snapshot.apiKeyStored)
            """

        case .setScope:
            guard let proposed = ToolInvocation.proposedScope(from: invocation, current: scope()) else {
                throw ToolError.badArguments("could not build the new scope")
            }
            onScopeChanged?(proposed)
            return "Scope is now: \(Self.describe(proposed))."

        case .setYoloMode(let on):
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            await controls.setYolo(on)
            return on ? "YOLO mode is on for this session." : "YOLO mode is off; risky actions ask again."

        case .setAutoApproveMedium(let on):
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            await controls.setAutoApproveMedium(on)
            return on ? "Medium-risk actions no longer ask." : "Medium-risk actions ask again."

        case .setYoloAsksAfterUntrusted(let on):
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            await controls.setYoloAsksAfterUntrusted(on)
            return on ? "YOLO mode asks again after network content was read."
                      : "YOLO mode no longer asks after network content was read."

        case .listModels:
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            let models = try await controls.listModels()
            tainted = true
            let text = models.isEmpty ? "(no models returned)" : models.map { "\($0.id): \($0.name)" }.joined(separator: "\n")
            return Untrusted.wrap(text, source: "provider model catalog", nonce: nonce)

        case .testConnection:
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            try await controls.testConnection()
            return "The selected model replied to the test prompt."

        case .setEngagement(let enabled, let profile):
            guard let controls else { throw ToolError.badArguments("settings unavailable") }
            let state = EngagementState(active: enabled, profile: profile, startedAt: enabled ? Date() : nil)
            await controls.setEngagement(state)
            if enabled {
                return "Engagement is armed (\(profile.summary)). \(profile.note.isEmpty ? "" : "Scope note: \(profile.note). ")"
                    + "The banner shows it and everything is audited."
            }
            return "Engagement is off. Normal approval rules apply again."

        case .exploitCheck(let module, let host, let port):
            return await exploit(ExploitRegistry.modules[module]!, .init(host: host, port: port), checkOnly: true)

        case .exploitRun(let module, let host, let port):
            return await exploit(ExploitRegistry.modules[module]!, .init(host: host, port: port), checkOnly: false)

        case .authSpray(let service, let host, let port, let path):
            return await spray(service: service, host: host, port: port, path: path)
        }
    }

    // MARK: helpers

    private func exploit(_ module: any ExploitModule, _ target: ExploitTarget, checkOnly: Bool) async -> String {
        let outcome = checkOnly
            ? await module.check(target, probe: probe, caps: ScopeCaps())
            : await module.run(target, probe: probe, caps: ScopeCaps())
        await findings.noteHost(target.host.string)
        tainted = true
        if outcome.verdict == .open {
            await findings.add(Finding(
                severity: .high, host: target.host.string, port: target.effectivePort(module),
                module: module.name,
                title: outcome.summary,
                detail: "The module interaction succeeded without authentication; evidence is attached to this finding.",
                recommendation: "Restrict the service, require authentication, or take it out of the network segment.",
                evidence: String(outcome.evidence.summary.prefix(2_000))))
        }
        let redacted = await LootScanner.redact(outcome.evidence.responses.joined(separator: "\n"),
                                                source: module.name, loot: loot)
        return """
        \(module.name): \(outcome.verdict.rawValue) — \(outcome.summary)
        \(Untrusted.wrap(outcome.evidence.summary + lootNote(redacted.ids), source: module.name, nonce: nonce))
        """
    }

    private func spray(service: String, host: IPv4Address, port: UInt16?, path: String) async -> String {
        await findings.noteHost(host.string)
        tainted = true
        let result: AuthSpray.Result
        let usedPort: UInt16
        switch service {
        case "http_basic":
            usedPort = port ?? 80
            result = await AuthSpray.httpBasic(host: host, port: usedPort, path: path.isEmpty ? "/" : path,
                                               probe: probe, caps: ScopeCaps())
        default:
            usedPort = port ?? 6379
            result = await AuthSpray.redis(host: host, port: usedPort, probe: probe, caps: ScopeCaps())
        }
        if let accepted = result.accepted {
            await findings.add(Finding(
                severity: .high, host: host.string, port: usedPort, module: "auth_spray",
                title: "\(service) accepted a bundled default credential",
                detail: "The fixed bundle (\(result.attempts.count) attempts, 1/s) found working credentials.",
                recommendation: "Change the credential, disable the service or move it off the shared segment.",
                evidence: result.evidence.joined(separator: "\n").prefix(2_000).description))
        }
        // The accepted credential becomes loot: stored for the approval dialog, only
        // referenced here, never in the transcript.
        var acceptedLine = "no bundle credential was accepted"
        var ids: [String] = []
        if let accepted = result.accepted,
           let id = await loot.add(kind: "credential",
                                   source: "auth_spray \(host.string):\(usedPort)",
                                   value: "\(accepted.user.map { "\($0):" } ?? "")\(accepted.password)") {
            acceptedLine = "ACCEPTED \(accepted.user ?? "-") → [loot:\(id)] (stored; shown in the approval dialog)"
            ids = [id]
        }
        return Untrusted.wrap("""
        auth_spray \(service) \(host.string):\(usedPort): \(acceptedLine)
        attempts: \(result.attempts.map { "\($0.user ?? "-") → \($0.detail)" }.joined(separator: "; "))\(lootNote(ids))
        """, source: "auth_spray \(host.string)", nonce: nonce)
    }

    /// The targets a validated call wants to touch, in the terms the scope speaks.
    private func scopeTargets(_ invocation: ToolInvocation) async -> [ScopeTarget] {
        switch invocation {
        case .getNetworkContext, .browseBonjour, .getFindings, .exportReport, .getAuditLog,
             .getAppSettings, .setYoloMode, .setAutoApproveMedium, .setYoloAsksAfterUntrusted,
             .listModels, .testConnection, .setEngagement, .recordFinding:
            return []
        case .discoverHosts(let cidr): return [.hosts(cidr, count: Int(cidr.hostCount))]
        case .scanPorts(let host, let ports): return [.host(host), .ports(ports)]
        case .grabBanner(let host, let port): return [.host(host), .port(port)]
        case .httpRequest(_, let url, _, _):
            guard let hostString = url.host, let address = IPv4Address(hostString) else {
                return [.name(url.host ?? "")]
            }
            return [.url(host: address, port: UInt16(url.port ?? (url.scheme == "https" ? 443 : 80)))]
        case .dnsLookup(let name, _): return [.name(name)]
        case .setScope: return []
        case .exploitCheck(_, let host, let port), .exploitRun(_, let host, let port):
            var targets: [ScopeTarget] = [.host(host)]
            if let port { targets.append(.port(port)) }
            return targets
        case .authSpray(_, let host, let port, _):
            var targets: [ScopeTarget] = [.host(host)]
            if let port { targets.append(.port(port)) }
            return targets
        }
    }

    public static func describe(_ policy: ScopePolicy) -> String {
        guard !policy.cidrs.isEmpty || !policy.denyHosts.isEmpty else { return "none set" }
        var parts = ["networks \(policy.cidrs.map(\.string).joined(separator: ", "))"]
        if !policy.denyHosts.isEmpty { parts.append("deny \(policy.denyHosts.map(\.string).joined(separator: ", "))") }
        parts.append("ports \(policy.ports.isEmpty ? "(none)" : "\(policy.ports.count) allowed")")
        if let window = policy.window {
            parts.append("window until \(window.end.formatted(date: .abbreviated, time: .shortened))")
        }
        parts.append("caps hosts \(policy.caps.maxHosts)/ports \(policy.caps.maxPorts)/concurrency \(policy.caps.maxConcurrency)")
        return parts.joined(separator: ", ")
    }

    private func lootNote(_ ids: [String]) -> String {
        ids.isEmpty ? "" : "\n[loot] stored \(ids.count) item(s): \(ids.map { "[loot:\($0)]" }.joined(separator: " "))"
    }
}

extension ExploitTarget {
    func effectivePort(_ module: any ExploitModule) -> UInt16? { port ?? module.defaultPort }
}

/// The Bonjour service types the app declares in Info.plist, so browsing needs no
/// multicast entitlement.
public enum BonjourTypes {
    public static let declared = [
        "_airplay._tcp", "_raop._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
        "_workstation._tcp", "_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_ipp._tcp", "_printer._tcp",
        "_googlecast._tcp", "_spotify-connect._tcp", "_hap._tcp", "_companion-link._tcp", "_rdlink._tcp",
    ]
}
