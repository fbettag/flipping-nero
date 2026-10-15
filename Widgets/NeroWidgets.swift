import ActivityKit
import SwiftUI
import WidgetKit

@main
struct NeroWidgets: WidgetBundle {
    var body: some Widget {
        NeroLiveActivity()
    }
}

private let accent = Color(red: 1.0, green: 0.16, blue: 0.18)

struct NeroLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: RunActivityAttributes.self) { context in
            LockScreenView(context: context)
                .activityBackgroundTint(Color.black.opacity(0.88))
                .activitySystemActionForegroundColor(accent)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Logo(size: 38).padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Trailing(context: context).font(.title3.monospacedDigit().weight(.semibold))
                        .foregroundStyle(accent).padding(.trailing, 4)
                }
                DynamicIslandExpandedRegion(.center) {
                    Text(context.state.phase).font(.headline).lineLimit(1)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 8) {
                        if context.state.approvalPending {
                            ApprovalRow(context: context)
                        } else {
                            Text(context.state.detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            if let progress = context.state.progress {
                                ProgressView(value: progress).tint(accent)
                            }
                            Button(intent: StopRunIntent()) {
                                Label("Stop", systemImage: "stop.fill").font(.caption.weight(.semibold))
                            }.tint(.gray)
                        }
                    }
                }
            } compactLeading: {
                Logo(size: 20)
            } compactTrailing: {
                Trailing(context: context).font(.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(accent).frame(maxWidth: 44)
            } minimal: {
                Logo(size: 20)
            }
            .keylineTint(accent)
        }
    }
}

private struct LockScreenView: View {
    let context: ActivityViewContext<RunActivityAttributes>

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Logo(size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(context.attributes.runTitle).font(.headline).foregroundStyle(.white).lineLimit(1)
                    Text(context.state.phase).font(.caption.monospaced().weight(.semibold)).foregroundStyle(accent)
                }
                Spacer()
                Trailing(context: context).font(.subheadline.monospacedDigit().weight(.semibold)).foregroundStyle(accent)
                if !context.state.isFinished {
                    Button(intent: StopRunIntent()) {
                        Label("Stop", systemImage: "stop.fill").font(.caption.weight(.semibold))
                    }.tint(.gray)
                }
            }
            if context.state.approvalPending {
                ApprovalRow(context: context)
            } else {
                HStack(spacing: 12) {
                    Label("\(context.state.hostsSeen) hosts", systemImage: "personalhotspot")
                    Label("\(context.state.findings) findings", systemImage: "flag.2.crossed")
                }
                .font(.caption.monospacedDigit()).foregroundStyle(.white.opacity(0.75))
                if let progress = context.state.progress {
                    ProgressView(value: progress).tint(accent)
                }
                Text(context.state.detail).font(.caption).foregroundStyle(.white.opacity(0.6)).lineLimit(2)
            }
        }
        .padding(14)
    }
}

/// The approval step with its summary. Allow needs device authentication;
/// Deny does not. The buttons resolve the exact step the run is waiting on.
private struct ApprovalRow: View {
    let context: ActivityViewContext<RunActivityAttributes>

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(context.state.approvalSummary)
                .font(.caption.weight(.semibold)).foregroundStyle(.white).lineLimit(3)
            HStack(spacing: 10) {
                Button(intent: ApproveStepIntent()) {
                    Label("Allow", systemImage: "checkmark").font(.caption.weight(.bold))
                        .frame(maxWidth: .infinity)
                }
                .tint(accent)
                Button(intent: DenyStepIntent()) {
                    Label("Deny", systemImage: "xmark").font(.caption.weight(.bold))
                        .frame(maxWidth: .infinity)
                }
                .tint(.gray)
            }
        }
    }
}

/// Run timer while active, checkmark when finished.
private struct Trailing: View {
    let context: ActivityViewContext<RunActivityAttributes>

    var body: some View {
        if context.state.isFinished {
            Image(systemName: "checkmark")
        } else {
            Text(context.attributes.startedAt, style: .timer).multilineTextAlignment(.trailing)
        }
    }
}

private struct Logo: View {
    let size: CGFloat
    var body: some View {
        Image("Logo").resizable().scaledToFit().frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
    }
}
