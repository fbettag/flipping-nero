import Foundation
import AgentKit
import NeroKit

/// App-level functions the agent can reach, so everything the UI offers is also
/// available in chat. Loosening only ever arrives here after the executor obtained
/// explicit consent; implementations apply it without asking again.
struct AppControlsBridge: AppControls {
    /// The model is a process-wide singleton; the reference is kept for clarity.
    private let model: AppModel
    init(model: AppModel) { self.model = model }

    func settings() async -> AppSettingsSnapshot {
        await MainActor.run {
            AppSettingsSnapshot(
                yolo: model.yolo,
                yoloAsksAfterUntrusted: model.yoloAsksAfterUntrusted,
                autoApproveMedium: UserDefaults.standard.bool(forKey: AppModel.autoApproveKey),
                engagementActive: model.engagement.active,
                engagementSummary: model.engagement.active ? model.engagement.profile.summary : "off",
                scopeSummary: model.scope.map { ToolExecutor.describe($0) } ?? "none set",
                model: model.currentModel,
                provider: model.aiProvider.rawValue,
                apiKeyStored: model.hasAPIKey && !model.isDemo)
        }
    }

    func setYolo(_ enabled: Bool) async {
        await MainActor.run { model.yolo = enabled }
    }

    func setAutoApproveMedium(_ enabled: Bool) async {
        await MainActor.run {
            UserDefaults.standard.set(enabled, forKey: AppModel.autoApproveKey)
        }
    }

    func setYoloAsksAfterUntrusted(_ enabled: Bool) async {
        await MainActor.run { model.yoloAsksAfterUntrusted = enabled }
    }

    func setEngagement(_ state: EngagementState) async {
        await MainActor.run { model.applyEngagement(state, audit: false) }
    }

    func setModel(_ newModel: String) async {
        await MainActor.run {
            var settings = model.aiSettings
            settings.model = newModel
            model.applyAISettings(settings)
        }
    }

    func setProvider(_ provider: AIProvider, baseURL: String?) async throws {
        try await MainActor.run {
            model.selectProvider(provider)
            if let baseURL {
                var settings = model.aiSettings
                settings.baseURL = baseURL
                model.applyAISettings(settings)
            }
        }
    }

    func listModels() async throws -> [AIModel] {
        let settings = await MainActor.run { model.aiSettings }
        let key = KeychainStore.read(settings.provider.rawValue) ?? ""
        return try await settings.api(key: key).models()
    }

    func testConnection() async throws {
        let settings = await MainActor.run { model.aiSettings }
        let key = KeychainStore.read(settings.provider.rawValue) ?? ""
        try await settings.api(key: key).test(model: settings.model)
    }
}
