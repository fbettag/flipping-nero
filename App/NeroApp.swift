import SwiftUI
import AgentKit

@main
struct NeroApp: App {
    @State private var model = AppModel.shared
    @Environment(\.scenePhase) private var scenePhase

    init() {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("-noSplash") { /* reserved for a later splash */ }
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .task { launch() }
                .sheet(item: Binding(get: { model.pendingApproval }, set: { _ in })) { pending in
                    ApprovalSheet(pending: pending)
                        .environment(model)
                        .preferredColorScheme(.dark)
                        .tint(Theme.accent)
                        .interactiveDismissDisabled()
                }
        }
        .onChange(of: scenePhase) { model.setScenePhase(scenePhase) }
    }

    /// Debug builds understand NE_DEMO=1 (sample data, no network or API key needed) and
    /// NE_DEMO_APPROVAL=1 (with a pending approval sheet), for UI review and screenshots.
    /// NE_DEMO_RUN=1 turns Run taps into a scripted demo run through the real UI pipeline.
    /// Launch arguments: -nero_autorun taps Run after two seconds, -nero_tab=N opens that
    /// tab, -nero_tabwalk cycles through the tabs every six seconds.
    private func launch() {
        #if DEBUG
        let env = ProcessInfo.processInfo.environment
        if env["NE_DEMO"] == "1" {
            model.loadDemo(withApproval: env["NE_DEMO_APPROVAL"] == "1")
        }
        let arguments = ProcessInfo.processInfo.arguments
        if let tabArgument = arguments.first(where: { $0.hasPrefix("-nero_tab=") }),
           let tab = Int(tabArgument.dropFirst("-nero_tab=".count)) {
            model.selectedTab = tab
        }
        if arguments.contains("-nero_autorun") {
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(2))
                _ = try? await model.startRun()
            }
        }
        if arguments.contains("-nero_tabwalk") {
            Task { @MainActor in
                for tab in [1, 2, 3, 4, 0] {
                    try? await Task.sleep(for: .seconds(7))
                    model.selectedTab = tab
                }
            }
        }
        #endif
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        TabView(selection: Binding(get: { model.selectedTab }, set: { model.selectedTab = $0 })) {
            RunView().tabItem { Label("Run", systemImage: "bolt.horizontal.circle") }.tag(0)
            ChatView().tabItem { Label("Chat", systemImage: "bubble.left.and.text.bubble.right") }.tag(1)
            FindingsView().tabItem { Label("Findings", systemImage: "flag.2.crossed") }.tag(2)
            AuditView().tabItem { Label("Audit", systemImage: "list.clipboard") }.tag(3)
            SettingsView().tabItem { Label("Settings", systemImage: "gearshape") }.tag(4)
        }
    }
}
