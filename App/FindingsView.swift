import SwiftUI
import NeroKit

/// Findings of the run plus the shareable reports. The loot index is redacted by design;
/// full values live in the approval dialogs and nowhere else.
struct FindingsView: View {
    @Environment(AppModel.self) private var model
    @State private var findings: [Finding] = []

    var body: some View {
        NavigationStack {
            List {
                if !findings.isEmpty {
                    Section("Findings (\(findings.count))") {
                        ForEach(findings) { finding in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(finding.severity.rawValue.uppercased())
                                        .font(.caption2.weight(.heavy).monospaced())
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(severityColor(finding.severity), in: .capsule)
                                        .foregroundStyle(.white)
                                    Text(finding.title).font(.subheadline.weight(.semibold))
                                }
                                Text("\(finding.host)\(finding.port.map { ":\($0)" } ?? "") · \(finding.module)")
                                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                                if !finding.detail.isEmpty {
                                    Text(finding.detail).font(.caption).foregroundStyle(.secondary)
                                }
                                if !finding.recommendation.isEmpty {
                                    Label(finding.recommendation, systemImage: "lightbulb")
                                        .font(.caption2).foregroundStyle(Theme.warn)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }

                Section("Reports") {
                    let files = model.reports()
                    if files.isEmpty {
                        Text("No reports yet. They are written at the end of a run, or when you stop one.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(files, id: \.absoluteString) { file in
                        ShareLink(item: file) {
                            Label(file.lastPathComponent, systemImage: "doc.richtext")
                                .font(.subheadline.monospaced())
                        }
                    }
                }

                Section {
                    Text("The loot index stays redacted: what was found and where, never the value itself. Full values appear once, in their approval dialog.")
                        .font(.caption2).foregroundStyle(.secondary)
                } footer: { EmptyView() }
            }
            .overlay {
                if findings.isEmpty && model.reports().isEmpty {
                    Text("Nothing found yet. Start a run.")
                        .foregroundStyle(.secondary)
                }
            }
            .themedList()
            .brandedNavigation("Findings")
            .task { await reload() }
            .refreshable { await reload() }
            .onChange(of: model.findingCount) { Task { await reload() } }
        }
    }

    private func reload() async {
        findings = await AppModel.shared.currentFindings()
    }

    private func severityColor(_ severity: Severity) -> Color {
        switch severity {
        case .info: .gray
        case .low: Theme.ok
        case .medium: Theme.warn
        case .high, .critical: Theme.danger
        }
    }
}
