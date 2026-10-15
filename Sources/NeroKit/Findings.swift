import Foundation

public enum Severity: String, Codable, Sendable, CaseIterable, Comparable {
    case info, low, medium, high, critical

    public static func < (a: Severity, b: Severity) -> Bool {
        (allCases.firstIndex(of: a) ?? 0) < (allCases.firstIndex(of: b) ?? 0)
    }
}

/// A structured, code-validated finding. The model proposes; the parser validates
/// every field; the report carries the truncated evidence, never raw tool bodies.
public struct Finding: Codable, Identifiable, Sendable, Equatable {
    public let id: UUID
    public var date: Date
    public var severity: Severity
    public var host: String
    public var port: UInt16?
    public var module: String
    public var title: String
    public var detail: String
    public var recommendation: String
    /// Truncated evidence text; the full evidence stays in the run transcript only.
    public var evidence: String

    public init(severity: Severity, host: String, port: UInt16?, module: String, title: String,
                detail: String, recommendation: String, evidence: String) {
        self.id = UUID()
        self.date = Date()
        self.severity = severity
        self.host = host
        self.port = port
        self.module = module
        self.title = title
        self.detail = detail
        self.recommendation = recommendation
        self.evidence = evidence
    }
}

/// Everything a run saw and concluded. Session-scoped; the report is written from it.
public actor FindingStore {
    public private(set) var findings: [Finding] = []
    public private(set) var seenHosts: Set<String> = []
    public private(set) var startedAt = Date()

    public init() {}

    public func noteHost(_ host: String) {
        seenHosts.insert(host)
    }

    /// Adds a finding unless the same host, port, module and title already exists.
    /// Returns false for duplicates.
    @discardableResult
    public func add(_ finding: Finding) -> Bool {
        let duplicate = findings.contains {
            $0.host == finding.host && $0.port == finding.port && $0.module == finding.module
                && $0.title == finding.title
        }
        guard !duplicate else { return false }
        findings.append(finding)
        if !finding.host.isEmpty { seenHosts.insert(finding.host) }
        return true
    }

    public func snapshot() -> [Finding] { findings }

    public var counts: (hosts: Int, findings: Int) { (seenHosts.count, findings.count) }
}
