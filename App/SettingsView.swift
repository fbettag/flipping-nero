import SwiftUI
import AgentKit
import NeroKit

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage(AppModel.autoApproveKey) private var autoApproveMedium = false
    @AppStorage(AppModel.pivotHostKey) private var pivotHost = ""
    @AppStorage(AppModel.pivotPortKey) private var pivotPort = "4444"
    @AppStorage(AppModel.pivotListenKey) private var pivotListenPort = "4444"
    @State private var confirmYolo = false
    @State private var showArmSheet = false

    var body: some View {
        NavigationStack {
            Form {
                AISettingsSection()

                Section {
                    Toggle("Skip prompts for medium-risk actions", isOn: $autoApproveMedium)
                } header: { Text("Approvals") } footer: {
                    Text("High-risk actions (exploit modules, credential spray, state-changing HTTP) always ask unless YOLO mode is on. After the agent has read content from the network, every offensive action asks again, even with this switch on.")
                }

                Section {
                    Toggle(isOn: Binding(
                        get: { model.yolo },
                        set: { on in if on { confirmYolo = true } else { model.yolo = false } }
                    )) {
                        Label("YOLO mode", systemImage: "flame.fill").foregroundStyle(model.yolo ? Theme.danger : .primary)
                    }
                    if model.yolo {
                        @Bindable var model = model
                        Toggle("Still ask after network content", isOn: $model.yoloAsksAfterUntrusted)
                    }
                } header: { Text("YOLO") } footer: {
                    Text("Scans, banners and checks run without asking. Blocked targets, the scope and the caps stay blocked. Stays on across restarts until you turn it off; turning it on always asks. With the second switch on, the agent still asks after reading banners or HTTP bodies, which is where planted instructions would live.")
                }

                Section {
                    Toggle("Keep screen awake while a run is active", isOn: Binding(
                        get: { model.keepAwake },
                        set: { model.keepAwake = $0 }))
                } header: { Text("Background") } footer: {
                    Text("While a run is in the foreground the screen stays awake. If you lock the phone anyway, iOS 26's continued processing keeps the run going and the Lock Screen shows its state. If the system ends the background time, the run saves a partial report and pauses.")
                }

                Section {
                    LabeledContent("Status", value: model.engagement.active
                        ? "Armed (\(model.engagement.profile.summary))"
                        : "Off")
                    if model.engagement.active {
                        if !model.engagement.profile.note.isEmpty {
                            LabeledContent("Scope note", value: model.engagement.profile.note)
                        }
                        Button("Disarm", role: .destructive) {
                            model.applyEngagement(.inactive, audit: true)
                        }
                    } else {
                        Button("Arm engagement...") { showArmSheet = true }
                    }
                } header: { Text("Engagement and capabilities") } footer: {
                    Text("Pre-approves actions for this session and arms capabilities: exploit unlocks exploit_check, exploit_run and auth_spray; cloud_readonly allows one explicitly named link-local target. Blocked targets and the scope stay blocked, everything is audited, and it disarms on restart. The agent can request arming in chat, but only you can confirm it.")
                }

                Section {
                    TextField("Connect-back host (your handler)", text: $pivotHost)
                        .keyboardType(.URL).autocorrectionDisabled().textInputAutocapitalization(.never)
                    TextField("Connect-back port", text: $pivotPort)
                        .keyboardType(.numberPad)
                    TextField("Listen port inside the LAN", text: $pivotListenPort)
                        .keyboardType(.numberPad)
                    LabeledContent("Status", value: pivotStatus)
                    if model.pivotRunning {
                        Button("Stop relay", role: .destructive) { model.stopPivot() }
                    } else {
                        Button("Start relay") { model.startPivot() }
                            .disabled(!pivotConfigValid || !model.engagement.armed(\.pivot) || model.scope?.isArmed != true)
                        if let reason = pivotBlockedReason {
                            Text(reason).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                } header: { Text("Pivot relay (meterpreter bridge)") } footer: {
                    Text("Bridges TCP sessions from this LAN to your listener outside: point reverse_tcp payloads at this phone's LAN IP and the listen port, and run your handler (e.g. exploit/multi/handler) on the connect-back host and port. Only peers inside the scope are bridged, everything else is dropped and audited. Needs an armed scope and engagement with the pivot capability; disarming stops the relay. The agent cannot start this.")
                }

                Section {
                    NavigationLink("Audit log") { AuditView() }
                    Link("Readme (repo)", destination: URL(string: "https://github.com/2342/flipping-nero")!)
                }
            }
            .themedList()
            .brandedNavigation("Settings")
            .sheet(isPresented: $showArmSheet) { EngagementArmSheet() }
            .confirmationDialog("Enable YOLO mode?", isPresented: $confirmYolo, titleVisibility: .visible) {
                Button("Enable YOLO", role: .destructive) { model.yolo = true }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Scans, banners and checks run without asking until the app restarts. Planted content from the network could mislead the agent unless the second switch stays on. Only this session.")
            }
        }
    }

    private var pivotConfigValid: Bool {
        let host = pivotHost.trimmingCharacters(in: .whitespaces)
        let connect = UInt16(pivotPort.trimmingCharacters(in: .whitespaces)) ?? 0
        let listen = UInt16(pivotListenPort.trimmingCharacters(in: .whitespaces)) ?? 0
        return !host.isEmpty && (1...65535).contains(Int(connect)) && (1...65535).contains(Int(listen))
    }

    /// Why Start relay is greyed out, in the order the operator can fix it.
    private var pivotBlockedReason: String? {
        if !pivotConfigValid { return "Enter a connect-back host and valid ports first." }
        if !model.engagement.armed(\.pivot) { return "Arm engagement with the pivot capability first." }
        if model.scope?.isArmed != true { return "Start a run once so a scope is armed." }
        return nil
    }

    private var pivotStatus: String {
        if model.pivotRunning {
            let stats = model.pivotStats
            return "\(stats.active) active · \(stats.bridged) bridged · \(stats.rejected) dropped · \(stats.up)/\(stats.down) B"
        }
        return model.engagement.armed(\.pivot) ? "Off" : "Off (pivot capability not armed)"
    }
}

/// The operator arms engagement here: capabilities, scope note, then a deliberate hold.
struct EngagementArmSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var autoApprovals = true
    @State private var exploit = false
    @State private var pivot = false
    @State private var cloudReadonly = false
    @State private var note = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Run actions without prompts", isOn: $autoApprovals)
                    Toggle("Exploit modules and credential spray", isOn: $exploit)
                    Toggle("Field Node (pivot)", isOn: $pivot)
                    Toggle("One explicit link-local target (cloud_readonly)", isOn: $cloudReadonly)
                } header: { Text("Capabilities") } footer: {
                    Text("Exploit checks touch services on purpose: anonymous logins, unauthenticated commands, default credentials from the fixed bundle. Pivot is reserved for the Field Node and does nothing yet.")
                }
                Section {
                    TextField("Scope note, e.g. client name or floor", text: $note)
                } header: { Text("Scope") } footer: {
                    Text("Shown on the banner and given to the agent, so it can tell what is in scope.")
                }
                Section {
                    HoldToConfirm(label: "Hold to arm") {
                        model.applyEngagement(EngagementState(
                            active: true,
                            profile: EngagementProfile(
                                capabilities: Capabilities(autoApprovals: autoApprovals, exploit: exploit,
                                                           pivot: pivot, cloudReadonly: cloudReadonly),
                                note: note),
                            startedAt: .now), audit: true)
                        dismiss()
                    }
                }
            }
            .themedList()
            .navigationTitle("Engagement")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}
