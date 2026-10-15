import SwiftUI
import AgentKit

/// The append-only trail: every tool call with its risk and the decision that
/// authorized it. This is what the report timeline is built from.
struct AuditView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List(model.auditRecords) { record in
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(record.summary).font(.subheadline)
                    Spacer()
                    Text(record.decision.rawValue).font(.caption).foregroundStyle(color(record))
                }
                HStack {
                    Text(record.date.formatted(date: .abbreviated, time: .standard))
                    if let risk = record.risk { Text("risk \(Self.riskName(risk))") }
                    Text(record.succeeded ? "ok" : "failed").foregroundStyle(record.succeeded ? Theme.ok : Theme.danger)
                }
                .font(.caption2).foregroundStyle(.secondary)
                if !record.detail.isEmpty {
                    Text(record.detail).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .overlay { if model.auditRecords.isEmpty { Text("No actions yet").foregroundStyle(.secondary) } }
        .themedList()
        .brandedNavigation("Audit")
        .toolbar {
            if !model.auditRecords.isEmpty {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: auditReport()) {
                        Label("Export report", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
        .task { await model.loadAudit() }
        .refreshable { await model.loadAudit() }
    }

    private func auditReport() -> String {
        let records = Array(model.auditRecords.reversed())
        return RunReport(title: model.runTitle.isEmpty ? "Audit" : model.runTitle,
                         scope: model.scope, records: records,
                         findings: [], lootIndex: []).markdown()
    }

    private static func riskName(_ risk: RiskLevel) -> String {
        switch risk {
        case .low: "low"
        case .medium: "medium"
        case .high: "high"
        case .blocked: "blocked"
        }
    }

    private func color(_ r: AuditRecord) -> Color {
        switch r.decision {
        case .denied, .blocked, .invalid, .yolo, .engaged: .red
        case .approved, .shortcut: .orange
        case .auto: .secondary
        case .skippedNeedsForeground: .yellow
        }
    }
}
