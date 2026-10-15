import BackgroundTasks
import SwiftUI
import Foundation
import Observation
import UIKit
import AgentKit
import NeroKit

struct ChatEntry: Identifiable {
    enum Kind { case user, assistant, tool, error }
    enum ToolStatus { case running, ok, error, denied, blocked }
    let id = UUID()
    var kind: Kind
    var text: String
    var tool = ""
    var status = ToolStatus.ok
    var output = ""
}

struct PendingApproval: Identifiable {
    let id = UUID()
    let request: ApprovalRequest
    fileprivate let continuation: CheckedContinuation<Bool, Never>?
}

@MainActor @Observable
final class AppModel {
    /// One model for the whole process, so Siri and the Lock Screen drive the same run as the UI.
    static let shared = AppModel()

    enum RunPhase: String {
        case idle, discover, ports, checks, report, finished, paused
    }

    nonisolated static let autoApproveKey = "autoApproveMedium"
    nonisolated static let keepAwakeKey = "keepAwakeDuringRun"
    nonisolated static let pivotHostKey = "pivotConnectHost"
    nonisolated static let pivotPortKey = "pivotConnectPort"
    nonisolated static let pivotListenKey = "pivotListenPort"
    nonisolated static let yoloKey = "yoloMode"
    nonisolated static let yoloAsksKey = "yoloAsksAfterUntrusted"

    // Run state
    var selectedTab = 0
    private(set) var runTitle = ""
    private(set) var runPhase: RunPhase = .idle
    private(set) var runStartedAt: Date?
    private(set) var runError: String?
    private(set) var hostsSeen = 0
    private(set) var findingCount = 0
    private(set) var lastToolSummary = ""
    /// The run's closing words, shown on the Run tab so the end state explains itself.
    private(set) var lastRunSummary = ""
    var scope: ScopePolicy?

    // Chat and approvals
    var chat: [ChatEntry] = []
    var isBusy = false
    /// True while a run turn or chat turn is inside the loop, including slow model
    /// replies. Drives the thinking indicator so long provider latency is not silence.
    private(set) var agentThinking = false
    var pendingApproval: PendingApproval?
    var auditRecords: [AuditRecord] = []

    // YOLO persists across restarts (operator's call); arming it still always needs the
    // consent dialog. Engagement stays session-only by design.
    var yolo = UserDefaults.standard.bool(forKey: AppModel.yoloKey) {
        didSet {
            UserDefaults.standard.set(yolo, forKey: AppModel.yoloKey)
            syncPolicy()
        }
    }
    var yoloAsksAfterUntrusted = (UserDefaults.standard.object(forKey: AppModel.yoloAsksKey) as? Bool) ?? true {
        didSet {
            UserDefaults.standard.set(yoloAsksAfterUntrusted, forKey: AppModel.yoloAsksKey)
            syncPolicy()
        }
    }
    var engagement = EngagementState.inactive { didSet { syncPolicy() } }
    private(set) var aiProvider = AIProvider(rawValue: UserDefaults.standard.string(forKey: AISettings.providerKey) ?? "") ?? .openrouter
    private var aiSettingsRevision = 0
    var aiSettings: AISettings {
        _ = aiSettingsRevision
        return AISettings.load(aiProvider)
    }
    var currentModel: String { aiSettings.model }
    var hasAPIKey: Bool {
        _ = aiSettingsRevision
        return isDemo || !(KeychainStore.read(aiProvider.rawValue) ?? "").isEmpty
    }

    private let policyBox = PolicyBox()
    private let scopeBox = ScopeBox()
    private let foregroundBox = ForegroundBox()
    private(set) var isForeground = true
    private(set) var isDemo = false

    let liveActivities = LiveActivityController()
    let background = BackgroundRunController()

    // Pivot relay: operator-only, started from Settings with the pivot capability armed.
    private(set) var pivotStats = PivotRelay.Stats()
    private(set) var pivotRunning = false
    private var pivotRelay: PivotRelay?

    private var session: AgentSession?
    private var retiredSession: AgentSession?
    private var runTask: Task<Void, Never>?
    private var findings = FindingStore()
    private var loot = LootStore()
    private let audit = FileAuditLog(url: URL.applicationSupportDirectory.appending(path: "audit.jsonl"))
    private var liveApprovalContinuation: CheckedContinuation<Bool, Never>?
    private var liveApprovalTimeout: Task<Void, Never>?
    /// Serializes agent turns: the run loop, operator chat and Siri instructions take
    /// turns on the same session instead of interleaving inside the actor.
    private let turnLock = TurnLock()

    var isRunActive: Bool {
        switch runPhase {
        case .discover, .ports, .checks, .report: true
        default: false
        }
    }

    var keepAwake: Bool {
        get { UserDefaults.standard.object(forKey: Self.keepAwakeKey) as? Bool ?? true }
        set {
            UserDefaults.standard.set(newValue, forKey: Self.keepAwakeKey)
            syncIdleTimer()
        }
    }

    private init() {
        liveActivities.endStale()
        let relay = PivotRelay { [weak self] event in
            Task { @MainActor in self?.handlePivotEvent(event) }
        }
        pivotRelay = relay
    }

    // MARK: Pivot relay

    /// Bridges LAN-side TCP sessions to the operator's handler outside. Requires an
    /// armed engagement with the pivot capability and an armed scope; peers outside the
    /// scope are dropped and audited.
    func startPivot() {
        guard engagement.armed(\.pivot) else { return }
        guard let policy = scopeBox.current, policy.isArmed else { return }
        guard let relay = pivotRelay, !relay.isRunning else { return }
        let host = UserDefaults.standard.string(forKey: Self.pivotHostKey) ?? ""
        let connectPort = UInt16(UserDefaults.standard.integer(forKey: Self.pivotPortKey))
        let listenPort = UInt16(UserDefaults.standard.integer(forKey: Self.pivotListenKey))
        do {
            try relay.start(config: PivotRelay.Config(listenPort: listenPort, connectHost: host,
                                                      connectPort: connectPort)) { [scopeBox] address in
                guard let current = scopeBox.current else { return false }
                return ScopeGuard.check([.host(address)], policy: current) == .ok
            }
            Task { await audit.record(.init(
                tool: "pivot_relay",
                summary: "Pivot relay started: listen \(listenPort == 0 ? relay.assignedPort.map(String.init) ?? "?" : String(listenPort)) → \(host):\(connectPort)",
                risk: .high, decision: .approved, succeeded: true, detail: "from Settings")) }
        } catch {
            AppLog.error("pivot start failed: \(error)")
            Task { await audit.record(.init(
                tool: "pivot_relay", summary: "Pivot relay failed to start: \(error)",
                risk: .high, decision: .blocked, succeeded: false, detail: "invalid configuration")) }
        }
    }

    func stopPivot(reason: String = "stopped by the operator") {
        pivotRelay?.stop(reason: reason)
    }

    private func handlePivotEvent(_ event: PivotRelay.Event) {
        switch event {
        case .started(let config):
            pivotRunning = true
            AppLog.info("pivot relay up on port \(pivotRelay?.assignedPort.map(String.init) ?? "?") "
                + "→ \(config.connectHost):\(config.connectPort)")
        case .bridged(let peer):
            Task { await audit.record(.init(
                tool: "pivot_relay", summary: "Bridged \(peer) to the operator handler",
                risk: .high, decision: .engaged, succeeded: true, detail: "")) }
        case .rejected(let peer):
            Task { await audit.record(.init(
                tool: "pivot_relay", summary: "Dropped out-of-scope peer \(peer)",
                risk: .high, decision: .blocked, succeeded: false, detail: "peer outside the scope")) }
        case .closed(let peer, let up, let down, let reason):
            Task { await audit.record(.init(
                tool: "pivot_relay", summary: "Bridge \(peer) closed: \(reason)",
                risk: .high, decision: .engaged, succeeded: true, detail: "up \(up) B, down \(down) B")) }
        case .failed(let why):
            AppLog.error("pivot: \(why)")
        case .stopped:
            pivotRunning = false
        }
        pivotStats = pivotRelay?.stats ?? PivotRelay.Stats()
    }

    private func syncPolicy() {
        policyBox.set(yolo: yolo, asksAfterUntrusted: yoloAsksUntrustedRaw, engagement: engagement)
    }
    private var yoloAsksUntrustedRaw: Bool { yoloAsksAfterUntrusted }

    func setScenePhase(_ phase: ScenePhase) {
        isForeground = phase == .active
        foregroundBox.set(phase == .active)
        syncIdleTimer()
        // Coming back to the front: a pending live approval is resolved in the app instead.
        if phase == .active, liveApprovalContinuation != nil {
            finishLiveApproval(false)
        }
    }

    /// The screen stays awake while a run is in the foreground; locking falls back to the
    /// background task. Reset whenever the run ends, pauses or the app goes to the back.
    func syncIdleTimer() {
        UIApplication.shared.isIdleTimerDisabled = isForeground && keepAwake && isRunActive
    }

    // MARK: AI settings

    func selectProvider(_ provider: AIProvider) {
        aiProvider = provider
        UserDefaults.standard.set(provider.rawValue, forKey: AISettings.providerKey)
        aiSettingsRevision += 1
        session = nil
        retiredSession = nil
        if !isBusy { newChat() }
    }

    func applyAISettings(_ settings: AISettings) {
        settings.persist()
        aiProvider = settings.provider
        aiSettingsRevision += 1
        session = nil
        retiredSession = nil
        if !isBusy { newChat() }
    }

    // MARK: Approvals

    func resolveApproval(_ approved: Bool) {
        guard let pending = pendingApproval else { return }
        pendingApproval = nil
        pending.continuation?.resume(returning: approved)
    }

    /// The Lock Screen buttons resolve the pending run step. Allow arrives authenticated
    /// (the intent declares requiresLocalDeviceAuthentication); Deny does not need it.
    @discardableResult
    func resolveLiveApproval(_ approved: Bool) async -> Bool {
        guard liveApprovalContinuation != nil else { return false }
        finishLiveApproval(approved)
        return true
    }

    private func finishLiveApproval(_ approved: Bool) {
        liveApprovalTimeout?.cancel()
        liveApprovalTimeout = nil
        let continuation = liveApprovalContinuation
        liveApprovalContinuation = nil
        liveActivities.approvalResolved()
        chat.append(ChatEntry(kind: .tool, text: "Lock Screen decision: \(approved ? "allow" : "deny")",
                              tool: "lock_screen", status: approved ? .ok : .denied))
        continuation?.resume(returning: approved)
    }

    /// Presents an approval request: in the app as a sheet, in the background on the
    /// Lock Screen with a 60 second timeout. Timeout counts as denied; the run continues.
    func presentApproval(_ request: ApprovalRequest) async -> Bool {
        await withCheckedContinuation { continuation in
            if isForeground {
                pendingApproval = PendingApproval(request: request, continuation: continuation)
            } else {
                liveApprovalContinuation = continuation
                liveActivities.approvalPending(summary: request.summary)
                chat.append(ChatEntry(kind: .tool, text: "Waiting on the Lock Screen: \(request.summary)",
                                      tool: request.tool, status: .running))
                liveApprovalTimeout = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(60))
                    guard !Task.isCancelled else { return }
                    await MainActor.run { self?.finishLiveApproval(false) }
                }
            }
        }
    }

    // MARK: Engagement

    /// Applies arming from either the arm dialog (audited) or an approved agent request
    /// (already audited by the executor). Disarming is always free.
    func applyEngagement(_ state: EngagementState, audit: Bool) {
        guard state != engagement else { return }
        engagement = state
        if !state.active { stopPivot(reason: "engagement disarmed") }
        if audit {
            let invocation = ToolInvocation.setEngagement(enabled: state.active, profile: state.profile)
            let risk = RiskAssessor.assess(invocation)
            Task { await self.audit.record(.init(
                tool: invocation.toolName, summary: invocation.summary, risk: risk.level,
                decision: .approved, succeeded: true, detail: "from Settings")) }
        }
        Task { await session?.updateEngagement(state) }
    }

    // MARK: The run

    /// One tap: title from the SSID, scope from the interface subnet, the default profile,
    /// YOLO and capabilities as last set. No form. `cidr` overrides the auto subnet when
    /// the operator typed a different block on the Run tab.
    func startRun(cidr override: IPv4CIDR? = nil) async throws -> String {
        #if DEBUG
        if ProcessInfo.processInfo.environment["NE_DEMO_RUN"] == "1" {
            return await startDemoRun()
        }
        #endif
        guard !isRunActive else { return runTitle }
        runError = nil
        let cidr: IPv4CIDR
        if let override {
            cidr = override
        } else if let auto = NetworkIdentity.localScope(startedAt: Date()) {
            cidr = auto
        } else {
            throw RunError.noLAN("No Wi-Fi interface with an IPv4 address was found. "
                + "Cellular (pdp_ip0) is never a LAN scope; join the Wi-Fi you want to assess and try again.")
        }
        // Belt and braces for weird netmasks: a run never arms a block wider than /20,
        // the same limit set_scope enforces ("ein /8 ist kein gültiges Argument").
        guard cidr.prefix >= IPv4CIDR.minimumPrefix else {
            throw RunError.noLAN("The subnet \(cidr.string) is too wide to be a scope. "
                + "This usually means an unusual interface; join a normal LAN Wi-Fi and try again.")
        }
        runTitle = await NetworkIdentity.runTitle()
        let policy = ScopePolicy.localSubnet(cidr)
        scopeBox.set(policy)
        scope = policy
        findings = FindingStore()
        loot = LootStore()
        runStartedAt = Date()
        runPhase = .discover
        hostsSeen = 0
        findingCount = 0
        lastRunSummary = ""
        chat = []
        syncIdleTimer()
        liveActivities.runStarted(title: runTitle,
                                  detail: ToolExecutor.describe(policy))
        await background.submit(title: runTitle)

        do {
            let session = try await ensureRunSession()
            self.session = session
            runTask = Task { [weak self] in
                guard let self else { return }
                do {
                    let answer = try await self.turnLocked {
                        try await session.send(
                            "Start the run: get the network context, discover the live hosts in scope, "
                                + "scan the interesting ones, check for unauthenticated services, record findings "
                                + "as you go, and finish with export_report.")
                    }
                    finishRun(success: true, summary: answer)
                } catch {
                    AppLog.error("run failed: \(error)")
                    finishRun(success: false, summary: "\(error)")
                }
            }
            return runTitle
        } catch {
            scopeBox.set(nil)
            scope = nil
            runPhase = .idle
            runStartedAt = nil
            liveActivities.runEnded()
            background.finish(success: false)
            syncIdleTimer()
            throw error
        }
    }

    /// Stops the run, saves a partial report and disarms. Stopping is always free.
    @discardableResult
    func stopRun() async -> Bool {
        guard isRunActive else { return false }
        runTask?.cancel()
        runTask = nil
        await writePartialReport(reason: "stopped by the operator")
        finishRun(success: false, summary: "Run stopped; a partial report was saved.")
        return true
    }

    #if DEBUG
    /// NE_DEMO_RUN=1: a scripted run that drives the real UI pipeline (chat entries,
    /// progress, findings, report) without an API key, for simulator walkthroughs.
    private func startDemoRun() async -> String {
        guard !isRunActive else { return runTitle }
        runTitle = "Demo LAN"
        let cidr = NetworkIdentity.localScope(startedAt: Date()) ?? IPv4CIDR("192.168.178.0/24")!
        let policy = ScopePolicy.localSubnet(cidr)
        scopeBox.set(policy)
        scope = policy
        findings = FindingStore()
        loot = LootStore()
        runStartedAt = Date()
        runPhase = .discover
        hostsSeen = 0
        findingCount = 0
        lastRunSummary = ""
        chat = []
        agentThinking = true
        liveActivities.runStarted(title: runTitle, detail: ToolExecutor.describe(policy))
        runTask = Task { [weak self] in
            await self?.demoScript()
        }
        return runTitle
    }

    private func demoScript() async {
        func pause(_ seconds: Double) async { try? await Task.sleep(for: .seconds(seconds)) }
        func toolDone(_ name: String) {
            guard let i = chat.lastIndex(where: { $0.kind == .tool && $0.tool == name && $0.status == .running })
            else { return }
            chat[i].status = .ok
        }
        // The demo drives the same audit trail a real run leaves behind.
        func audited(_ tool: String, _ summary: String, risk: RiskLevel, decision: AuditRecord.Decision) async {
            await audit.record(.init(tool: tool, summary: summary, risk: risk,
                                     decision: decision, succeeded: true, detail: ""))
        }

        await pause(1.5)
        apply(.assistantText("Sweeping the demo LAN. I'll report as I go."))
        chat.append(ChatEntry(kind: .tool, text: "Read the phone's own network context",
                              tool: "get_network_context", status: .running))
        await pause(1.2)
        toolDone("get_network_context")
        if let i = chat.lastIndex(where: { $0.tool == "get_network_context" }) {
            chat[i].output = "interface: en0\nown_ip: \(scope?.cidrs.first?.address.string ?? "192.168.178.42")\nsubnet: \(scope?.cidrs.first?.string ?? "192.168.178.0/24")"
        }
        await audited("get_network_context", "Read the phone's own network context", risk: .low, decision: .auto)

        chat.append(ChatEntry(kind: .tool, text: "Discover live hosts in \(scope?.cidrs.first?.string ?? "192.168.178.0/24")",
                              tool: "discover_hosts", status: .running))
        for done in 1...12 {
            if Task.isCancelled { return }
            progress(kind: "discover", done: done, total: 12)
            await pause(0.3)
        }
        toolDone("discover_hosts")
        hostsSeen = 7
        await audited("discover_hosts", "Discover live hosts in \(scope?.cidrs.first?.string ?? "192.168.178.0/24")",
                      risk: .medium, decision: .approved)
        apply(.assistantText("7 hosts alive. Scanning the interesting ones."))

        for host in [".1", ".7", ".12"] {
            if Task.isCancelled { return }
            chat.append(ChatEntry(kind: .tool, text: "TCP connect-scan 192.168.178\(host) on top-100 ports",
                                  tool: "scan_ports", status: .running))
            for done in 1...6 {
                progress(kind: "ports", done: done, total: 6)
                await pause(0.25)
            }
            toolDone("scan_ports")
            await audited("scan_ports", "TCP connect-scan 192.168.178\(host) on 100 ports",
                          risk: .medium, decision: .yolo)
        }

        chat.append(ChatEntry(kind: .tool, text: "Run exploit check 'redis_unauth' against 192.168.178.12",
                              tool: "exploit_check", status: .running))
        await pause(1.5)
        toolDone("exploit_check")
        await audited("exploit_check", "Run exploit check 'redis_unauth' against 192.168.178.12",
                      risk: .high, decision: .engaged)
        await findings.add(Finding(
            severity: .high, host: "192.168.178.12", port: 6379, module: "redis_unauth",
            title: "Redis without authentication",
            detail: "PING answered +PONG without credentials.",
            recommendation: "Set requirepass or bind to localhost.",
            evidence: "redis_unauth 192.168.178.12:6379\n> PING\n< +PONG"))
        let counts = await findings.counts
        hostsSeen = counts.hosts
        findingCount = counts.findings
        apply(.assistantText("One high finding: unauthenticated Redis on .12. Writing the report."))

        chat.append(ChatEntry(kind: .tool, text: "Write the run report (markdown and JSON) into the app container",
                              tool: "export_report", status: .running))
        await pause(1.5)
        toolDone("export_report")
        await audited("export_report", "Write the run report (markdown and JSON) into the app container",
                      risk: .low, decision: .auto)
        await writePartialReport(reason: "demo run")
        agentThinking = false
        finishRun(success: true,
                  summary: "Demo run complete: 7 hosts, 1 finding, report saved. Open Findings to share it.")
    }
    #endif

    /// The system expired the background task: save state, mark the run paused.
    func pauseForExpiration() {
        guard isRunActive else { return }
        Task { await writePartialReport(reason: "background time expired") }
        runPhase = .paused
        retireRunSession()
        liveActivities.runChanged(phase: "paused", detail: "Saved a partial report. Resume with Run.",
                                  hosts: hostsSeen, findings: findingCount, progress: nil,
                                  approvalPending: false, approvalSummary: "", finished: true)
        background.finish(success: false)
        syncIdleTimer()
    }

    private func finishRun(success: Bool, summary: String) {
        runPhase = .finished
        lastRunSummary = summary
        retireRunSession()
        liveActivities.runChanged(phase: "finished", detail: summary,
                                  hosts: hostsSeen, findings: findingCount, progress: 1,
                                  approvalPending: false, approvalSummary: "", finished: true)
        background.finish(success: success)
        chat.append(ChatEntry(kind: .assistant, text: summary))
        syncIdleTimer()
        Task { await loadAudit() }
    }

    /// After a run ends, follow-up questions belong to a chat session (co-pilot persona),
    /// not the run prompt that demands a fresh autonomous run. The transcript carries over,
    /// so questions still see the run's findings and context.
    private func retireRunSession() {
        guard let current = session else { return }
        retiredSession = current
        session = nil
    }

    private func writePartialReport(reason: String) async {
        let records = await audit.recent(limit: 500)
        let list = await findings.snapshot()
        let lootIndex = await loot.index()
        let report = RunReport(title: runTitle, operatorNote: reason, scope: scopeBox.current,
                               records: records, findings: list, lootIndex: lootIndex)
        let directory = URL.documentsDirectory.appending(path: "Reports")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("\(report.fileNameBase).md")
        try? report.markdown().write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: Sessions

    private func makeExecutor(gate: ApprovalGate, approvedAs: AuditRecord.Decision) async -> ToolExecutor {
        let executor = ToolExecutor(
            probe: NWProbe(hostInScope: { [scopeBox] host in
                guard let address = IPv4Address(host) else { return false }
                return ScopeGuard.check([.host(address)], policy: scopeBox.current) == .ok
            }),
            findings: findings, loot: loot, audit: audit,
            gate: gate, controls: AppControlsBridge(model: AppModel.shared),
            settings: { [policyBox] in
                let flags = policyBox.snapshot
                return ApprovalSettings(
                    autoApproveMedium: UserDefaults.standard.bool(forKey: AppModel.autoApproveKey),
                    yolo: flags.yolo, yoloAsksAfterUntrusted: flags.asksAfterUntrusted,
                    engagement: flags.engagement)
            },
            scope: { [scopeBox] in scopeBox.current },
            onScopeChanged: { [weak self] policy in
                guard let self else { return }
                self.scopeBox.set(policy)
                Task { @MainActor in
                    self.scope = policy
                    Task { await self.session?.updateScope(policy) }
                }
            },
            isForeground: { [foregroundBox] in foregroundBox.isForeground },
            reportDirectory: URL.documentsDirectory.appending(path: "Reports"),
            reportTitle: { [runTitle = self.runTitle] in runTitle },
            vault: KeychainLootVault(),
            approvedAs: approvedAs)
        await executor.setProgressHandler { [weak self] kind, done, total in
            Task { @MainActor in self?.progress(kind: kind, done: done, total: total) }
        }
        return executor
    }

    private func progress(kind: String, done: Int, total: Int) {
        let phase: RunPhase = kind == "discover" ? .discover : .ports
        if isRunActive { runPhase = phase }
        hostsSeen = max(hostsSeen, done >= total && kind == "discover" ? done : hostsSeen)
        let fraction = total > 0 ? Double(done) / Double(total) : nil
        liveActivities.runChanged(phase: runPhase.rawValue, detail: "\(kind) \(done)/\(total)",
                                  hosts: hostsSeen, findings: findingCount, progress: fraction,
                                  approvalPending: liveApprovalContinuation != nil,
                                  approvalSummary: "", finished: false)
        background.updateProgress(fraction: fraction, phase: runPhase.rawValue)
    }

    private func ensureRunSession() async throws -> AgentSession {
        guard let key = KeychainStore.read(aiProvider.rawValue), !key.isEmpty else {
            throw ProviderError.missingKey
        }
        guard !currentModel.isEmpty else { throw ProviderError.missingModel }
        let llm = try aiSettings.api(key: key).client(model: currentModel)
        let executor = await makeExecutor(gate: RunApprovalGate(), approvedAs: .approved)
        let created = AgentSession(llm: llm, executor: executor, scope: scopeBox.current,
                                   engagement: engagement, runTitle: runTitle, isRun: true)
        await created.setMaxSteps(40)
        return created
    }

    private func ensureChatSession() async throws -> AgentSession {
        if let session { return session }
        guard let key = KeychainStore.read(aiProvider.rawValue), !key.isEmpty else {
            throw ProviderError.missingKey
        }
        guard !currentModel.isEmpty else { throw ProviderError.missingModel }
        let llm = try aiSettings.api(key: key).client(model: currentModel)
        let executor = await makeExecutor(gate: RunApprovalGate(), approvedAs: .approved)
        let carried = await retiredSession?.messages ?? []
        retiredSession = nil
        let created = AgentSession(llm: llm, executor: executor, history: carried,
                                   scope: scopeBox.current, engagement: engagement,
                                   runTitle: runTitle, isRun: false)
        session = created
        return created
    }

    func newChat() {
        denyPendingApproval()
        session = nil
        retiredSession = nil
        chat = []
    }

    private func denyPendingApproval() { resolveApproval(false) }

    /// One chat turn. During an active run the text goes to the running session instead,
    /// so the operator and Siri speak into the same loop.
    func send(_ text: String) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        chat.append(ChatEntry(kind: .user, text: trimmed))
        if isRunActive, let session {
            isBusy = true
            defer { isBusy = false }
            do {
                _ = try await turnLocked {
                    try await session.send(trimmed) { [weak self] event in
                        Task { @MainActor in self?.apply(event) }
                    }
                }
            } catch {
                AppLog.error("chat during run failed: \(error)")
                chat.append(ChatEntry(kind: .error, text: "\(error)"))
            }
            return
        }
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let session = try await ensureChatSession()
            let answer = try await turnLocked {
                try await session.send(trimmed) { [weak self] event in
                    Task { @MainActor in self?.apply(event) }
                }
            }
            chat.append(ChatEntry(kind: .assistant, text: answer))
        } catch {
            AppLog.error("chat failed: \(error)")
            chat.append(ChatEntry(kind: .error, text: "\(error)"))
        }
    }

    /// Siri's "Instruct Nero": free text into the running session. Without a run it
    /// refuses; Start run / Stop run exist as their own intents.
    func instruct(_ text: String) async throws -> String {
        guard isRunActive, let session else {
            throw RunError.noRun("No run is active. Say Start run first.")
        }
        isBusy = true
        defer { isBusy = false }
        let answer = try await turnLocked {
            try await session.send(text) { [weak self] event in
                Task { @MainActor in self?.apply(event) }
            }
        }
        return String(answer.prefix(400))
    }

    private func turnLocked(_ body: @escaping () async throws -> String) async throws -> String {
        await turnLock.acquire()
        agentThinking = true
        do {
            let result = try await body()
            agentThinking = false
            await turnLock.release()
            return result
        } catch {
            agentThinking = false
            await turnLock.release()
            throw error
        }
    }

    private func apply(_ event: AgentEvent) {
        switch event {
        case .assistantText(let text):
            // Reply text that arrived alongside tool calls: shown immediately so slow
            // model turns are narration the operator can read, not silence.
            chat.append(ChatEntry(kind: .assistant, text: text))
        case .toolStarted(let name, let summary):
            lastToolSummary = summary
            chat.append(ChatEntry(kind: .tool, text: summary, tool: name, status: .running))
            AppLog.debug("tool \(name): \(summary)")
            if isRunActive { liveActivities.runChanged(phase: runPhase.rawValue, detail: summary,
                                                       hosts: hostsSeen, findings: findingCount,
                                                       progress: nil,
                                                       approvalPending: liveApprovalContinuation != nil,
                                                       approvalSummary: "", finished: false) }
        case .toolFinished(let name, _, _, let result):
            AppLog.debug("tool \(name) finished: \(result.kind)")
            Task { [findings, loot] in
                let counts = await findings.counts
                await MainActor.run {
                    self.hostsSeen = counts.hosts
                    self.findingCount = counts.findings
                }
            }
            guard let i = chat.lastIndex(where: { $0.kind == .tool && $0.tool == name && $0.status == .running }) else { return }
            chat[i].status = switch result.kind {
            case .ok: .ok
            case .error: .error
            case .denied: .denied
            case .blocked: .blocked
            }
            chat[i].output = Self.preview(result.content)
        }
    }

    /// Strips the safety fences and shortens tool output for display.
    private static func preview(_ content: String) -> String {
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.hasPrefix("<<<") }
        let text = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        return text.count > 700 ? String(text.prefix(700)) + "\n..." : text
    }

    // MARK: Reports and audit

    /// Clears a finished or paused run so the Run tab shows the big button again.
    func resetFinishedRun() {
        guard !isRunActive else { return }
        runPhase = .idle
        runStartedAt = nil
    }

    func currentFindings() async -> [Finding] { await findings.snapshot() }

    func reports() -> [URL] {
        let directory = URL.documentsDirectory.appending(path: "Reports")
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "md" }.sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    func loadAudit() async {
        auditRecords = await audit.load().reversed()
    }

    #if DEBUG
    /// Seeds sample data so the UI can be reviewed in the simulator without a network or API key.
    func loadDemo(withApproval: Bool) {
        isDemo = true
        runTitle = "FritzBox-LAN"
        runPhase = .checks
        runStartedAt = Date().addingTimeInterval(-240)
        hostsSeen = 7
        findingCount = 2
        let cidr = IPv4CIDR("192.168.178.0/24")!
        scope = ScopePolicy.localSubnet(cidr)
        scopeBox.set(scope)
        chat = [
            ChatEntry(kind: .user, text: "Start the run"),
            ChatEntry(kind: .tool, text: "Read the phone's own network context", tool: "get_network_context",
                      status: .ok, output: "interface: en0\nown_ip: 192.168.178.42\nsubnet: 192.168.178.0/24\ngateway: 192.168.178.1"),
            ChatEntry(kind: .tool, text: "Discover live hosts in 192.168.178.0/24", tool: "discover_hosts",
                      status: .ok, output: "swept 254 hosts: 7 alive"),
            ChatEntry(kind: .tool, text: "Run exploit check 'redis_unauth' against 192.168.178.12", tool: "exploit_check",
                      status: .ok, output: "redis_unauth: open — Redis answers PING without authentication"),
            ChatEntry(kind: .assistant, text: "Found an unauthenticated Redis on .12 and an open FTP on .7. Writing findings and the report now."),
        ]
        if withApproval {
            let invocation = ToolInvocation.setYoloMode(true)
            let risk = RiskAssessor.assess(invocation)
            pendingApproval = PendingApproval(
                request: ApprovalRequest(tool: invocation.toolName, summary: invocation.summary, risk: risk.level,
                                         reasons: risk.reasons, isPermissionChange: invocation.requiresExplicitConsent),
                continuation: nil)
        }
    }
    #endif
}

/// A tiny async FIFO: one agent turn at a time on the shared session.
actor TurnLock {
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !busy {
            busy = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if let next = waiters.first {
            waiters.removeFirst()
            next.resume()
        } else {
            busy = false
        }
    }
}

enum RunError: Error, CustomStringConvertible {
    case noLAN(String)
    case noRun(String)
    case busy
    public var description: String {
        switch self {
        case .noLAN(let why), .noRun(let why): why
        case .busy: "The agent is still working on something else."
        }
    }
}

/// Routes approval requests to the app sheet or, in the background, to the Lock Screen.
final class RunApprovalGate: ApprovalGate, @unchecked Sendable {
    func decide(_ request: ApprovalRequest) async -> Bool {
        await AppModel.shared.presentApproval(request)
    }
}
