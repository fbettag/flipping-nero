import SwiftUI
import AgentKit
import NeroKit

/// The One-Tap run: no form. Title comes from the SSID, scope from the interface subnet
/// (editable, for the cases where the target is not the immediate LAN), profile from the
/// defaults. Missing permissions make the button the prompt.
struct RunView: View {
    @Environment(AppModel.self) private var model
    @State private var starting = false
    @State private var startError: String?
    @State private var proposedCIDR = ""
    @State private var seededScope = false

    /// The block the Run button will arm: the typed one when valid, else the auto subnet.
    private var plannedCIDR: IPv4CIDR? {
        let trimmed = proposedCIDR.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return autoCIDR }
        return IPv4CIDR(trimmed)
    }

    private var autoCIDR: IPv4CIDR? {
        NetworkIdentity.localScope(startedAt: Date())
    }

    private var scopeHint: String? {
        let trimmed = proposedCIDR.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, IPv4CIDR(trimmed) == nil else { return nil }
        return "Not a valid block. Use CIDR notation with at least /\(IPv4CIDR.minimumPrefix), e.g. 10.0.0.0/24."
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.background.ignoresSafeArea()
                Theme.glow
                ScrollView {
                    VStack(spacing: 18) {
                        if model.isRunActive || model.runPhase == .paused || model.runPhase == .finished {
                            statusCard
                        } else {
                            runButton
                        }
                        if let startError {
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                Text(startError).font(.footnote).foregroundStyle(Theme.warn).textSelection(.enabled)
                            }
                            .font(.footnote).foregroundStyle(Theme.warn)
                            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Theme.warn.opacity(0.14), in: .rect(cornerRadius: 12))
                        }
                        if model.isRunActive {
                            activeScopeCard
                        } else {
                            scopeEditor
                        }
                        Text("Every network action passes scope, risk, approval and audit. The model never decides the risk.")
                            .font(.caption).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 24)
                    }
                    .padding()
                }
            }
            .brandedNavigation("Run")
            .onAppear {
                if !seededScope {
                    proposedCIDR = autoCIDR?.string ?? ""
                    seededScope = true
                }
            }
        }
    }

    private var runButton: some View {
        VStack(spacing: 12) {
            Button {
                guard let cidr = plannedCIDR else { return }
                starting = true
                startError = nil
                Task {
                    defer { starting = false }
                    do {
                        // Stay on the Run tab: the status card shows phase, hosts and
                        // findings; the operator opens Chat on their own terms.
                        _ = try await AppModel.shared.startRun(cidr: cidr)
                    } catch {
                        startError = "\(error)"
                    }
                }
            } label: {
                HStack(spacing: 10) {
                    if starting {
                        ProgressView().tint(.white)
                    } else {
                        Image(systemName: "bolt.fill").font(.title2.weight(.bold))
                    }
                    Text(starting ? "Starting…" : "Run").font(.title2.weight(.heavy))
                }
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
                .background(plannedCIDR == nil ? Color.gray : Theme.accent,
                            in: .rect(cornerRadius: 20, style: .continuous))
            }
            .buttonStyle(.plain)
            .disabled(plannedCIDR == nil || starting)
            .sensoryFeedback(.impact(weight: .heavy), trigger: starting)
            Text("Starts a recon run on the block below: discover, ports, unauth checks, findings, report.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .padding(.top, 40)
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.runTitle).font(.headline)
                    Text(model.runPhase.rawValue.uppercased())
                        .font(.caption.monospaced().weight(.heavy)).foregroundStyle(Theme.accent)
                }
                Spacer()
                if model.isRunActive {
                    ProgressView().controlSize(.small).tint(Theme.accent)
                    Button("Stop", role: .destructive) {
                        Task { await AppModel.shared.stopRun() }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            Divider().overlay(Theme.stroke)
            HStack(spacing: 18) {
                stat("hosts", model.hostsSeen)
                stat("findings", model.findingCount)
                if let started = model.runStartedAt, model.isRunActive || model.runPhase == .paused {
                    VStack(alignment: .leading) {
                        Text("elapsed").font(.caption2).foregroundStyle(.secondary)
                        Text(started, style: .timer).font(.callout.monospacedDigit())
                    }
                }
                Spacer()
            }
            if model.isRunActive {
                if !model.lastToolSummary.isEmpty {
                    Text(model.lastToolSummary)
                        .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                }
                Button {
                    model.selectedTab = 1
                } label: {
                    Label("Open transcript", systemImage: "bubble.left.and.text.bubble.right")
                        .font(.footnote.weight(.semibold))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            } else {
                // The end state explains itself: summary plus where to go next.
                if !model.lastRunSummary.isEmpty {
                    Text(model.lastRunSummary)
                        .font(.footnote).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                HStack(spacing: 10) {
                    Button {
                        model.selectedTab = 1
                    } label: {
                        Label("Chat", systemImage: "bubble.left.and.text.bubble.right")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    Button {
                        model.selectedTab = 2
                    } label: {
                        Label("Findings", systemImage: "flag.2.crossed")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    Button {
                        model.resetFinishedRun()
                    } label: {
                        Label("Run again", systemImage: "bolt.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                }
                .controlSize(.small)
            }
        }
        .padding(16)
        .background(Theme.card, in: .rect(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Theme.stroke))
    }

    private func stat(_ label: String, _ value: Int) -> some View {
        VStack(alignment: .leading) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text("\(value)").font(.title3.monospacedDigit().weight(.semibold))
        }
    }

    /// The armed scope while a run is live; not editable, `set_scope` in chat can tighten it.
    private var activeScopeCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Scope (armed)", systemImage: "shield.lefthalf.filled")
                .font(.subheadline.weight(.semibold))
            if let scope = model.scope {
                Text(ToolExecutor.describe(scope))
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Theme.card, in: .rect(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Theme.stroke))
    }

    /// Before a run: the block it will sweep, editable for when the target is not the
    /// immediate LAN. Pre-filled with the interface subnet.
    private var scopeEditor: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Scope", systemImage: "shield.lefthalf.filled")
                .font(.subheadline.weight(.semibold))
            HStack(spacing: 8) {
                TextField("192.168.178.0/24", text: $proposedCIDR)
                    .font(.callout.monospaced())
                    .keyboardType(.asciiCapable)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .padding(10)
                    .background(Theme.background, in: .rect(cornerRadius: 10, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(scopeHint == nil ? Theme.stroke : Theme.warn))
                Button {
                    proposedCIDR = autoCIDR?.string ?? ""
                } label: {
                    Image(systemName: "arrow.counterclockwise")
                }
                .buttonStyle(.bordered)
                .disabled(proposedCIDR == (autoCIDR?.string ?? ""))
            }
            if let scopeHint {
                Text(scopeHint).font(.caption2).foregroundStyle(Theme.warn)
            } else if let planned = plannedCIDR {
                Text("Will sweep \(planned.string) (\(planned.hostCount) addresses). The interface subnet is the default; type another block when the target is not this LAN.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Theme.card, in: .rect(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Theme.stroke))
    }
}
