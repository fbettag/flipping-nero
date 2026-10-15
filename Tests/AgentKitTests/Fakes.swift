import Foundation
import NeroKit
@testable import AgentKit

/// A canned network: every wire the fake answers was configured by the test, and every
/// contact attempt is recorded so tests can prove that denied or out-of-scope calls
/// touched nothing.
final class FakeProbe: NetworkProbe, @unchecked Sendable {
    private let lock = NSLock()
    private var contacts: [String] = []
    private var pingable: Set<String> = []
    private var connectable: Set<String> = []
    private var banners: [String: Data] = [:]
    /// Answers per host:port, consumed in order like a scripted service.
    private var exchanges: [String: [Data]] = [:]
    private var httpRoutes: [String: HTTPResponse] = [:]
    private var dnsAnswers: [String: [DNSRecord]] = [:]
    private var bonjourResult: [BonjourService] = []

    func seed(host: IPv4Address, port: UInt16) {
        lock.withLock { connectable.insert("\(host.string):\(port)") }
    }

    func seedPing(host: IPv4Address) {
        lock.withLock { pingable.insert(host.string) }
    }

    func seedBanner(host: IPv4Address, port: UInt16, _ text: String) {
        lock.withLock { banners["\(host.string):\(port)"] = Data(text.utf8) }
    }

    /// Queues protocol answers; the last one repeats so run() interactions keep working.
    func seedExchange(host: IPv4Address, port: UInt16, _ answers: [String]) {
        lock.withLock {
            exchanges["\(host.string):\(port)"] = answers.map { Data($0.utf8) }
        }
    }

    func seedExchangeBytes(host: IPv4Address, port: UInt16, _ answers: [Data]) {
        lock.withLock { exchanges["\(host.string):\(port)"] = answers }
    }

    func seedHTTP(host: String, port: UInt16, path: String, _ response: HTTPResponse) {
        lock.withLock { httpRoutes["\(host):\(port)\(path)"] = response }
    }

    func seedDNS(name: String, _ records: [DNSRecord]) {
        lock.withLock { dnsAnswers[name] = records }
    }

    func seedBonjour(_ services: [BonjourService]) {
        lock.withLock { bonjourResult = services }
    }

    func contacted() -> [String] {
        lock.withLock { contacts }
    }

    private func record(_ line: String) {
        lock.withLock { contacts.append(line) }
    }

    // MARK: NetworkProbe

    func tcpConnect(_ host: IPv4Address, port: UInt16, timeout: Duration) async -> Bool {
        record("connect \(host.string):\(port)")
        return lock.withLock { connectable.contains("\(host.string):\(port)") }
    }

    func ping(_ host: IPv4Address, timeout: Duration) async -> Bool {
        record("ping \(host.string)")
        return lock.withLock { pingable.contains(host.string) }
    }

    func readBanner(_ host: IPv4Address, port: UInt16, timeout: Duration, maxBytes: Int) async -> Data? {
        record("banner \(host.string):\(port)")
        return lock.withLock { banners["\(host.string):\(port)"] }
    }

    func exchange(_ host: IPv4Address, port: UInt16, send: Data, timeout: Duration,
                  maxBytes: Int) async -> Data? {
        record("exchange \(host.string):\(port)")
        return lock.withLock {
            guard var queue = exchanges["\(host.string):\(port)"], !queue.isEmpty else { return nil }
            let answer = queue.removeFirst()
            exchanges["\(host.string):\(port)"] = queue.isEmpty ? [answer] : queue
            return answer
        }
    }

    func http(_ spec: HTTPRequestSpec, timeout: Duration) async throws -> HTTPResponse {
        let path = spec.url.path.isEmpty ? "/" : spec.url.path
        let port = spec.url.port ?? (spec.url.scheme == "https" ? 443 : 80)
        record("http \(spec.url.host ?? "?"):\(port)\(path)")
        return lock.withLock {
            httpRoutes["\(spec.url.host ?? "?"):\(port)\(path)"]
                ?? HTTPResponse(status: 404, headers: [:], body: Data())
        }
    }

    func queryDNS(_ name: String, rrtype: UInt16, timeout: Duration) async throws -> [DNSRecord] {
        record("dns \(name) type \(rrtype)")
        return lock.withLock { dnsAnswers[name] ?? [] }
    }

    func browseBonjour(_ types: [String], timeout: Duration) async -> [BonjourService] {
        record("bonjour \(types.joined(separator: ","))")
        return lock.withLock { bonjourResult }
    }
}

final class ScriptedGate: ApprovalGate, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [ApprovalRequest] = []
    var answer: Bool
    init(answer: Bool) { self.answer = answer }
    var requests: [ApprovalRequest] {
        lock.withLock { _requests }
    }
    func decide(_ request: ApprovalRequest) async -> Bool {
        lock.withLock { _requests.append(request) }
        return answer
    }
}

final class ScriptedLLM: LLMClient, @unchecked Sendable {
    private let lock = NSLock()
    private var script: [ChatMessage]
    private(set) var seenMessages: [[ChatMessage]] = []
    init(_ script: [ChatMessage]) { self.script = script }
    func complete(messages: [ChatMessage], tools: [ToolSpec]) async throws -> ChatMessage {
        lock.withLock {
            seenMessages.append(messages)
            return script.isEmpty ? ChatMessage(role: .assistant, content: "done") : script.removeFirst()
        }
    }
}

final class FakeAppControls: AppControls, @unchecked Sendable {
    private let lock = NSLock()
    private var _yolo = false
    private var _autoApproveMedium = false
    private var _yoloAsks = true
    private var _engagement = EngagementState.inactive
    private(set) var updatedModel = ""
    var yolo: Bool {
        get { lock.withLock { _yolo } }
        set { lock.withLock { _yolo = newValue } }
    }
    var autoApproveMedium: Bool {
        get { lock.withLock { _autoApproveMedium } }
        set { lock.withLock { _autoApproveMedium = newValue } }
    }
    var yoloAsksAfterUntrusted: Bool {
        get { lock.withLock { _yoloAsks } }
        set { lock.withLock { _yoloAsks = newValue } }
    }
    var engagement: EngagementState {
        get { lock.withLock { _engagement } }
        set { lock.withLock { _engagement = newValue } }
    }
    func settings() async -> AppSettingsSnapshot {
        AppSettingsSnapshot(
            yolo: yolo, yoloAsksAfterUntrusted: yoloAsksAfterUntrusted, autoApproveMedium: autoApproveMedium,
            engagementActive: engagement.active,
            engagementSummary: engagement.active ? engagement.profile.summary : "off",
            scopeSummary: "test scope", model: "test-model", provider: "openrouter", apiKeyStored: true)
    }
    func setYolo(_ enabled: Bool) async { yolo = enabled }
    func setAutoApproveMedium(_ enabled: Bool) async { autoApproveMedium = enabled }
    func setYoloAsksAfterUntrusted(_ enabled: Bool) async { yoloAsksAfterUntrusted = enabled }
    func setEngagement(_ state: EngagementState) async { engagement = state }
    func setModel(_ model: String) async { lock.withLock { updatedModel = model } }
    func setProvider(_ provider: AIProvider, baseURL: String?) async throws {}
    func listModels() async throws -> [AIModel] { [] }
    func testConnection() async throws {}
}

/// Records what the executor would have persisted into the Keychain.
final class FakeVault: LootVault, @unchecked Sendable {
    private let lock = NSLock()
    private var _persisted: [LootEntry] = []
    var persisted: [LootEntry] { lock.withLock { _persisted } }
    func persist(_ entries: [LootEntry]) async {
        lock.withLock { _persisted += entries }
    }
}

func toolCall(_ name: String, _ args: String = "{}", id: String = UUID().uuidString) -> ChatMessage {
    ChatMessage(role: .assistant, content: nil, toolCalls: [ToolCall(id: id, name: name, arguments: args)])
}
