import Foundation
import NeroKit

/// One run, one engagement, one shareable report: markdown plus JSON.
/// Contains scope, window, audit timeline, findings (with truncated evidence and a
/// recommendation) and the redacted loot index. Never contains provider keys, full
/// secrets, raw tool bodies or the system prompt.
public struct RunReport {
    public var title: String
    public var operatorNote: String
    public var generatedAt: Date
    public var scope: ScopePolicy?
    public var records: [AuditRecord]
    public var findings: [Finding]
    public var lootIndex: [LootEntry]

    public init(title: String, operatorNote: String = "", generatedAt: Date = Date(),
                scope: ScopePolicy?, records: [AuditRecord], findings: [Finding], lootIndex: [LootEntry]) {
        self.title = title
        self.operatorNote = operatorNote
        self.generatedAt = generatedAt
        self.scope = scope
        self.records = records
        self.findings = findings
        self.lootIndex = lootIndex
    }

    public var fileNameBase: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return "nero-run-\(formatter.string(from: generatedAt))"
    }

    /// Hosts the run saw versus hosts a finding names.
    public var hostSummary: String {
        let seen = Set(records.compactMap(Self.host(from:)))
            .union(findings.map(\.host))
        let withFinding = Set(findings.map(\.host))
        return "\(seen.count) hosts seen, \(withFinding.count) with findings"
    }

    /// Pulls IPv4 addresses out of audit summaries so the report counts real hosts.
    static func host(from record: AuditRecord) -> String? {
        guard let range = record.summary.range(of: #"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"#,
                                               options: .regularExpression) else { return nil }
        return String(record.summary[range])
    }

    public func markdown() -> String {
        var lines: [String] = []
        lines.append("# \(escape(title))")
        lines.append("")
        lines.append("- Generated: \(generatedAt.formatted(date: .abbreviated, time: .standard))")
        if !operatorNote.isEmpty { lines.append("- Operator note: \(escape(operatorNote))") }
        if let scope {
            lines.append("- Scope: \(escape(ToolExecutor.describe(scope)))")
            if let window = scope.window {
                lines.append("- Window: \(window.start.formatted(date: .abbreviated, time: .shortened)) to"
                             + " \(window.end.formatted(date: .abbreviated, time: .shortened))")
            }
        } else {
            lines.append("- Scope: none")
        }
        lines.append("- \(hostSummary)")

        var byDecision: [AuditRecord.Decision: Int] = [:]
        var failures = 0
        for record in records {
            byDecision[record.decision, default: 0] += 1
            if !record.succeeded { failures += 1 }
        }
        let decisions = byDecision.sorted { $0.key.rawValue < $1.key.rawValue }
            .map { "\($0.key.rawValue) \($0.value)" }.joined(separator: ", ")
        lines.append("- Outcome: \(failures) failed of \(records.count)\(decisions.isEmpty ? "" : " (\(decisions))")")

        lines.append("")
        lines.append("## Timeline")
        lines.append("")
        lines.append("| Time | Tool | Risk | Decision | Result | Summary |")
        lines.append("|---|---|---|---|---|---|")
        for record in records {
            let time = record.date.formatted(date: .abbreviated, time: .shortened)
            let risk = record.risk.map { "\($0)" } ?? "-"
            let result = record.succeeded ? "ok" : "failed"
            let summary = escape(record.detail.isEmpty ? record.summary : "\(record.summary) [\(record.detail)]")
            lines.append("| \(time) | \(escape(record.tool)) | \(risk) | \(record.decision.rawValue) | \(result) | \(summary) |")
        }

        lines.append("")
        lines.append("## Findings")
        lines.append("")
        if findings.isEmpty {
            lines.append("None.")
        } else {
            for (index, finding) in findings.enumerated() {
                lines.append("### #\(index + 1) [\(finding.severity.rawValue)] \(escape(finding.title))")
                lines.append("")
                lines.append("- Host: \(escape(finding.host))\(finding.port.map { ":\($0)" } ?? "") (module \(escape(finding.module)))")
                if !finding.detail.isEmpty { lines.append("- Detail: \(escape(finding.detail))") }
                if !finding.recommendation.isEmpty { lines.append("- Recommendation: \(escape(finding.recommendation))") }
                if !finding.evidence.isEmpty {
                    lines.append("- Evidence: `\(escape(String(finding.evidence.prefix(300))))`")
                }
                lines.append("")
            }
        }

        lines.append("## Loot index")
        lines.append("")
        if lootIndex.isEmpty {
            lines.append("Nothing found.")
        } else {
            for entry in lootIndex {
                lines.append("- \(entry.id) [\(entry.kind)] from \(escape(entry.source)) — value redacted, shown once in the approval dialog")
            }
        }
        lines.append("")
        lines.append("Approvals were enforced in code; the decision column shows how each action was authorized.")
        return lines.joined(separator: "\n")
    }

    public func json() -> Data {
        struct ReportJSON: Codable {
            var title: String
            var operatorNote: String
            var generatedAt: Date
            var scope: ScopePolicy?
            var hosts: String
            var decisions: [String: Int]
            var findings: [Finding]
            var loot: [LootIndexEntry]
        }
        struct LootIndexEntry: Codable {
            var id: String
            var kind: String
            var source: String
        }
        var decisions: [String: Int] = [:]
        for record in records { decisions[record.decision.rawValue, default: 0] += 1 }
        let payload = ReportJSON(
            title: title, operatorNote: operatorNote, generatedAt: generatedAt, scope: scope,
            hosts: hostSummary, decisions: decisions, findings: findings,
            loot: lootIndex.map { LootIndexEntry(id: $0.id, kind: $0.kind, source: $0.source) })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return (try? encoder.encode(payload)) ?? Data("{}".utf8)
    }

    /// Keeps the markdown tables intact even when summaries contain pipes or newlines.
    func escape(_ text: String) -> String {
        Untrusted.sanitizeName(text.replacingOccurrences(of: "|", with: "\\|"))
    }
}
