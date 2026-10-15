import Foundation
import AgentKit
import NeroKit

/// Persists approved loot values into the iOS Keychain. Values only ever arrive here
/// after the operator saw them in an approval sheet and approved; anything else stays
/// in the session's memory store.
struct KeychainLootVault: LootVault {
    func persist(_ entries: [LootEntry]) async {
        for entry in entries {
            _ = KeychainStore.write(entry.value, account: "loot.\(entry.id).\(entry.kind)")
        }
    }
}
