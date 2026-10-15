import SwiftUI
import AgentKit

struct ApprovalSheet: View {
    @Environment(AppModel.self) private var model
    let pending: PendingApproval

    private var request: ApprovalRequest { pending.request }
    private var isHigh: Bool { request.risk >= .high }

    private var title: String {
        request.isPermissionChange ? "Allow permission change?" : "Approve action"
    }

    private var icon: String {
        if request.isPermissionChange { return "lock.open.trianglebadge.exclamationmark" }
        return isHigh ? "exclamationmark.triangle.fill" : "hand.raised.fill"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    if request.isPermissionChange {
                        Text("The agent is asking for fewer prompts or more capability. You can turn this off again at any time in Settings or by asking the agent. Loosening is always a dialog like this one.")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                    if request.afterUntrustedContent {
                        Label(request.isPermissionChange
                              ? "This request came right after the agent read banners or responses from the network. Text planted there could have caused it. If you did not ask for this, deny."
                              : "The agent asked for this after reading content from the network. That content could contain hidden instructions. Only approve if you asked for exactly this.",
                              systemImage: "exclamationmark.shield.fill")
                            .font(.footnote)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.yellow.opacity(0.18), in: .rect(cornerRadius: 12, style: .continuous))
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(request.reasons, id: \.self) { reason in
                            Label(reason, systemImage: "smallcircle.filled.circle")
                                .font(.footnote).foregroundStyle(.secondary)
                                .labelStyle(.titleAndIcon)
                        }
                    }
                    if !request.lootPreviews.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Found credentials, shown once", systemImage: "key.fill")
                                .font(.subheadline.weight(.semibold))
                            ForEach(request.lootPreviews, id: \.id) { loot in
                                Text("\(loot.id) [\(loot.kind)]: \(loot.preview)")
                                    .font(.caption.monospaced())
                            }
                            Text("Full values are kept for use behind later, separately approved calls. They never appear in the report.")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.accent.opacity(0.10), in: .rect(cornerRadius: 12, style: .continuous))
                    }
                }
                .padding()
            }
            .safeAreaInset(edge: .bottom) { actions }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.large])
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(isHigh ? Theme.danger : Theme.accent)
                .frame(width: 44, height: 44)
                .background((isHigh ? Theme.danger : Theme.accent).opacity(0.15), in: .rect(cornerRadius: 12, style: .continuous))
            VStack(alignment: .leading, spacing: 6) {
                Text(request.summary).font(.headline)
                Text(isHigh ? "HIGH RISK" : "MEDIUM RISK")
                    .font(.caption2.weight(.heavy))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(isHigh ? Theme.danger : Theme.accent, in: .capsule)
                    .foregroundStyle(isHigh ? .white : .black)
            }
        }
    }

    private var actions: some View {
        VStack(spacing: 10) {
            Button { model.resolveApproval(false) } label: {
                Text("Deny").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)

            if isHigh {
                HoldToConfirm(label: request.isPermissionChange ? "Hold to allow" : "Hold to approve") {
                    model.resolveApproval(true)
                }
            } else {
                Button { model.resolveApproval(true) } label: {
                    Text("Approve").frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .background(.bar)
    }
}

/// A deliberate confirmation: the bar fills while the finger stays down; letting go early cancels.
struct HoldToConfirm: View {
    let label: String
    let onConfirm: () -> Void
    private static let duration = 1.2
    @State private var holding = false
    @State private var confirmed = false

    var body: some View {
        ZStack(alignment: .leading) {
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.danger.opacity(0.16))
            GeometryReader { geo in
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Theme.danger.opacity(0.55))
                    .frame(width: holding ? geo.size.width : 0)
                    .animation(holding ? .linear(duration: Self.duration) : .easeOut(duration: 0.2), value: holding)
            }
            Text(holding ? "Keep holding..." : label)
                .font(.headline)
                .frame(maxWidth: .infinity)
        }
        .frame(height: 50)
        .contentShape(.rect)
        .onLongPressGesture(minimumDuration: Self.duration, pressing: { holding = $0 }) {
            confirmed = true
            onConfirm()
        }
        .sensoryFeedback(.success, trigger: confirmed)
        .accessibilityLabel(label)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { onConfirm() }
    }
}
