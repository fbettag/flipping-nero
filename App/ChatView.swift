import SwiftUI

/// The operator's line to the running agent: chat in general, and during a run
/// instructions into the very same session, policy and audit.
struct ChatView: View {
    @Environment(AppModel.self) private var model
    @State private var input = ""
    @FocusState private var focused: Bool

    private var canSend: Bool {
        model.hasAPIKey && !model.isBusy && !input.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private static let suggestions: [(String, String)] = [
        ("network", "What is on this network?"),
        ("shield", "Check the usual unauthenticated services"),
        ("scope", "Only keep 10.0.0.0/24 in scope"),
        ("doc.text", "Give me the report now"),
    ]

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.background.ignoresSafeArea()
                Theme.glow
                VStack(spacing: 0) {
                    if !model.hasAPIKey { notice }
                    if model.engagement.active { engagementBanner }
                    if model.chat.isEmpty && !model.isBusy && !model.agentThinking { emptyState } else { transcript }
                    composer
                }
            }
            .brandedNavigation("Chat")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("New chat") { model.newChat() }
                        .disabled(model.isRunActive)
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { focused = false }.fontWeight(.semibold)
                }
            }
        }
    }

    private var notice: some View {
        Label("Add your API key in Settings", systemImage: "exclamationmark.circle")
            .font(.footnote.weight(.medium))
            .foregroundStyle(Theme.accent)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(Theme.accent.opacity(0.12), in: .capsule)
            .padding(.top, 4)
    }

    private var engagementBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "dot.radiowaves.left.and.right").font(.caption.weight(.bold))
            VStack(alignment: .leading, spacing: 0) {
                Text("ENGAGED").font(.caption.weight(.heavy).monospaced())
                if !model.engagement.profile.note.isEmpty {
                    Text(model.engagement.profile.note).font(.caption2).lineLimit(1)
                }
            }
            Spacer()
            Button("Disarm") { model.applyEngagement(.inactive, audit: true) }
                .font(.caption.weight(.semibold))
                .buttonStyle(.bordered)
                .controlSize(.mini)
        }
        .foregroundStyle(.white)
        .padding(.horizontal, 12).padding(.vertical, 7)
        .background(Theme.danger, in: .rect)
        .padding(.horizontal, 10).padding(.top, 6)
    }

    private var emptyState: some View {
        ScrollView {
            VStack(spacing: 22) {
                Image("Logo")
                    .resizable().scaledToFit()
                    .frame(width: 104, height: 104)
                    .clipShape(.rect(cornerRadius: 24, style: .continuous))
                    .shadow(color: Theme.accent.opacity(0.35), radius: 24)
                    .padding(.top, 40)
                VStack(spacing: 6) {
                    Text("Talk to Nero").font(.system(.title2, design: .rounded, weight: .bold))
                    Text("Scopes, scans and findings on the LAN you own. Approvals stay yours.")
                        .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                VStack(spacing: 10) {
                    ForEach(Self.suggestions, id: \.1) { icon, text in
                        Button {
                            input = text
                            Task { await model.send(text); input = "" }
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: icon).foregroundStyle(Theme.accent).frame(width: 24)
                                Text(text).font(.subheadline).multilineTextAlignment(.leading)
                                Spacer(minLength: 0)
                                Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(.tertiary)
                            }
                            .padding(14)
                            .background(Theme.card, in: .rect(cornerRadius: 14, style: .continuous))
                            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Theme.stroke))
                        }
                        .buttonStyle(.plain)
                        .disabled(!model.hasAPIKey)
                        .opacity(model.hasAPIKey ? 1 : 0.45)
                    }
                }
                .padding(.horizontal)
            }
        }
        .scrollDismissesKeyboard(.immediately)
        .simultaneousGesture(TapGesture().onEnded { focused = false })
    }

    private var transcript: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(model.chat) { entry in
                        EntryView(entry: entry).id(entry.id)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                    if model.isBusy || model.agentThinking { ThinkingBubble().id("thinking") }
                    Color.clear.frame(height: 1).id("bottom")
                }
                .padding(.horizontal)
                .padding(.top, 8)
                .animation(.snappy, value: model.chat.count)
            }
            .defaultScrollAnchor(.bottom)
            .scrollDismissesKeyboard(.immediately)
            .simultaneousGesture(TapGesture().onEnded { focused = false })
            .onChange(of: model.chat.count) { withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
            .onChange(of: model.isBusy) { withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
            .onChange(of: model.agentThinking) { withAnimation { proxy.scrollTo("bottom", anchor: .bottom) } }
        }
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 10) {
            TextField(model.isRunActive ? "Instruct the run…" : "Ask Nero…", text: $input, axis: .vertical)
                .focused($focused)
                .lineLimit(1...5)
                .submitLabel(.send)
                .onSubmit(send)
                .padding(.horizontal, 16).padding(.vertical, 11)
                .background(Theme.card, in: .rect(cornerRadius: 22, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(Theme.stroke))
            Button(action: send) {
                Image(systemName: "arrow.up")
                    .font(.headline.weight(.heavy))
                    .foregroundStyle(canSend ? .black : .gray)
                    .frame(width: 42, height: 42)
                    .background(canSend ? Theme.accent : Theme.card, in: .circle)
            }
            .disabled(!canSend)
            .sensoryFeedback(.impact(weight: .light), trigger: model.chat.count)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private func send() {
        guard canSend else { return }
        let text = input
        input = ""
        Task { await model.send(text) }
    }
}

private struct EntryView: View {
    let entry: ChatEntry

    var body: some View {
        switch entry.kind {
        case .user:
            HStack(alignment: .bottom) {
                Spacer(minLength: 56)
                Text(entry.text)
                    .font(.body).foregroundStyle(.black)
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Theme.accent, in: .rect(cornerRadius: 18, style: .continuous))
                    .textSelection(.enabled)
            }
        case .assistant:
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "cat.fill").font(.caption.weight(.bold)).foregroundStyle(.black)
                    .frame(width: 26, height: 26).background(Theme.accent, in: .circle)
                Text(Self.markdown(entry.text))
                    .font(.body)
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Theme.card, in: .rect(cornerRadius: 18, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.stroke))
                    .textSelection(.enabled)
                Spacer(minLength: 24)
            }
        case .tool:
            ToolCard(entry: entry)
        case .error:
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                // Errors must be copyable: they are the evidence when something breaks.
                Text(entry.text).font(.footnote).foregroundStyle(Theme.danger).textSelection(.enabled)
            }
            .font(.footnote).foregroundStyle(Theme.danger)
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.danger.opacity(0.12), in: .rect(cornerRadius: 12, style: .continuous))
        }
    }

    static func markdown(_ text: String) -> AttributedString {
        let text = text.split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.hasPrefix("- ") ? "\u{2022} " + $0.dropFirst(2) : String($0) }
            .joined(separator: "\n")
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }
}

private struct ToolCard: View {
    let entry: ChatEntry
    @State private var expanded = false

    private var tint: Color {
        switch entry.status {
        case .running: Theme.accent
        case .ok: Theme.ok
        case .error, .blocked: Theme.danger
        case .denied: Theme.warn
        }
    }

    private var symbol: String {
        switch entry.tool {
        case "get_network_context": "personalhotspot"
        case "discover_hosts": "mappin.and.ellipse"
        case "scan_ports": "door.left.hand.open"
        case "browse_bonjour": "antenna.radiowaves.left.and.right"
        case "grab_banner": "text.badge.star"
        case "http_request": "globe"
        case "dns_lookup": "a.magnify"
        case "record_finding": "flag.2.crossed"
        case "get_findings", "export_report": "doc.richtext"
        case "get_audit_log": "list.clipboard"
        case "get_app_settings", "set_yolo_mode", "set_engagement": "gearshape"
        case "set_scope": "shield.lefthalf.filled"
        case "exploit_check", "exploit_run": "wrench.and.screwdriver"
        case "auth_spray": "key"
        case "lock_screen": "lock.iphone"
        default: "wrench.and.screwdriver"
        }
    }

    private var statusLabel: String {
        switch entry.status {
        case .running: "running"
        case .ok: "done"
        case .error: "failed"
        case .denied: "denied"
        case .blocked: "blocked"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                guard !entry.output.isEmpty else { return }
                withAnimation(.snappy) { expanded.toggle() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: symbol).foregroundStyle(tint).frame(width: 22)
                    Text(entry.text)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.primary)
                        .lineLimit(2).multilineTextAlignment(.leading)
                    Spacer(minLength: 6)
                    if entry.status == .running {
                        ProgressView().controlSize(.small).tint(Theme.accent)
                    } else {
                        Text(statusLabel).font(.system(.caption2, design: .monospaced).weight(.semibold)).foregroundStyle(tint)
                        if !entry.output.isEmpty {
                            Image(systemName: "chevron.down").font(.caption2).foregroundStyle(.tertiary)
                                .rotationEffect(.degrees(expanded ? 180 : 0))
                        }
                    }
                }
                .padding(12)
            }
            .buttonStyle(.plain)

            if expanded {
                Divider().overlay(Theme.stroke)
                Text(entry.output)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .background(Theme.card, in: .rect(cornerRadius: 12, style: .continuous))
        .overlay(alignment: .leading) {
            Rectangle().fill(tint).frame(width: 3).clipShape(.rect(topLeadingRadius: 12, bottomLeadingRadius: 12))
        }
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Theme.stroke))
        .padding(.leading, 36)
    }
}

private struct ThinkingBubble: View {
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "cat.fill").font(.caption.weight(.bold)).foregroundStyle(.black)
                .frame(width: 26, height: 26).background(Theme.accent, in: .circle)
            TimelineView(.animation) { context in
                let t = context.date.timeIntervalSinceReferenceDate
                HStack(spacing: 8) {
                    ForEach(0..<3, id: \.self) { i in
                        Circle().fill(Theme.accent)
                            .frame(width: 7, height: 7)
                            .opacity(0.35 + 0.65 * max(0, sin(t * 4 - Double(i) * 0.7)))
                    }
                    Text("thinking…")
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 14)
            .background(Theme.card, in: .rect(cornerRadius: 18, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Theme.stroke))
        }
    }
}
