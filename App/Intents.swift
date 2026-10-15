import AppIntents
import AgentKit

// Siri and Shortcuts run through the same session, policy and audit as the UI.
// "Instruct Nero" sends operator text into the active run; Start run / Stop run
// manage the run itself. Approvals arrive as normal tool approvals; the Siri
// confirmation counts as the operator's decision and is audited as `shortcut`.

struct InstructNeroIntent: AppIntent {
    static let title: LocalizedStringResource = "Instruct Nero"
    static let description = IntentDescription("Sends free text to the running recon session. Does not start a run.")
    static let openAppWhenRun = false

    @Parameter(title: "Instruction", requestValueDialog: "What should Nero do?")
    var instruction: String

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let answer = try await AppModel.shared.instruct(instruction)
        return .result(value: answer, dialog: "\(answer)")
    }
}

struct StartRunIntent: AppIntent {
    static let title: LocalizedStringResource = "Start run"
    static let description = IntentDescription("Starts a recon run on the current subnet, like tapping Run.")
    static let openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let title = try await AppModel.shared.startRun()
        return .result(dialog: "Run started on \(title). Approvals show up on the Lock Screen.")
    }
}

struct NeroShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: InstructNeroIntent(),
                    phrases: ["Instruct \(.applicationName)", "Tell \(.applicationName)"],
                    shortTitle: "Instruct", systemImageName: "bubble.left.and.text.bubble.right")
        AppShortcut(intent: StartRunIntent(),
                    phrases: ["Start a run with \(.applicationName)"],
                    shortTitle: "Start run", systemImageName: "bolt.horizontal.circle")
        AppShortcut(intent: StopRunIntent(),
                    phrases: ["Stop the run with \(.applicationName)"],
                    shortTitle: "Stop run", systemImageName: "stop.circle")
    }
}
