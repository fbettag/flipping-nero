import Foundation

/// One secret found in network traffic or service output. The raw value lives here only;
/// transcripts, findings and reports carry the redacted form.
public struct LootEntry: Codable, Identifiable, Sendable, Equatable {
    public let id: String
    public var date: Date
    public var kind: String
    public var source: String
    /// The raw value. Never logged, never sent to the model, never in a report.
    public var value: String
    /// Short redacted form for UI lists.
    public var preview: String

    public init(id: String, kind: String, source: String, value: String) {
        self.id = id
        self.date = Date()
        self.kind = kind
        self.source = source
        self.value = value
        let head = String(value.prefix(4))
        self.preview = "\(head)…(\(value.count) chars)"
    }
}

/// Collects loot for the current session. Values go to the Keychain only after the
/// operator saw them in an approval; until then they stay in memory.
public actor LootStore {
    private(set) var entries: [LootEntry] = []
    private var seenValues: Set<String> = []

    public init() {}

    /// Stores a value once; returns the loot id or nil for duplicates.
    @discardableResult
    public func add(kind: String, source: String, value: String) -> String? {
        guard !value.isEmpty, !seenValues.contains(value) else { return nil }
        seenValues.insert(value)
        let id = "L\(entries.count + 1)"
        entries.append(LootEntry(id: id, kind: kind, source: source, value: value))
        return id
    }

    /// The redacted index that is safe for transcripts and reports.
    public func index() -> [LootEntry] { entries }

    public var isEmpty: Bool { entries.isEmpty }
}

/// Recognizes secret-shaped strings in tool output and redacts them before the text
/// reaches the model. What matches becomes loot; what the model sees is `[loot:Lx]`.
public enum LootScanner {
    public struct Candidate: Sendable, Equatable {
        public var kind: String
        public var value: String
    }

    static let patterns: [(String, NSRegularExpression)] = {
        func regex(_ kind: String, _ pattern: String) -> (String, NSRegularExpression)? {
            (try? NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines])).map { (kind, $0) }
        }
        return [
            regex("aws_access_key", #"AKIA[0-9A-Z]{16}"#),
            regex("aws_secret_key", #"(?i)aws.{0,20}secret[_ -]?access[_ -]?key.{0,20}['"\s:=]+([A-Za-z0-9/+=]{40})"#),
            regex("jwt", #"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"#),
            regex("private_key", #"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#),
            regex("credential", #"(?i)\b(password|passwd|pwd|secret|token|api[_ -]?key)\b['"\s:=]{1,3}['"]?([A-Za-z0-9!@#$%^&*()_+=./<>?;:-]{6,128})"#),
            regex("bearer_token", #"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._~+/=-]{16,512})"#),
        ].compactMap { $0 }
    }()

    /// Finds secret-shaped values in arbitrary text.
    public static func extract(_ text: String) -> [Candidate] {
        guard !text.isEmpty else { return [] }
        var found: [Candidate] = []
        for (kind, regex) in patterns {
            let range = NSRange(text.startIndex..., in: text)
            for match in regex.matches(in: text, options: [], range: range) {
                // Group 2 when the pattern has a capture group for the value, else the whole match.
                let valueRange = regex.numberOfCaptureGroups >= 2 && match.range(at: 2).location != NSNotFound
                    ? match.range(at: 2) : match.range
                guard let swiftRange = Range(valueRange, in: text) else { continue }
                let value = String(text[swiftRange])
                guard value.count >= 6 else { continue }
                found.append(Candidate(kind: kind, value: value))
            }
        }
        return found
    }

    /// Extracts loot from `text` and returns the text with every match replaced by its
    /// `[loot:id]` reference, plus the ids that were created.
    public static func redact(_ text: String, source: String, loot: LootStore) async -> (text: String, ids: [String]) {
        let candidates = extract(text)
        guard !candidates.isEmpty else { return (text, []) }
        var result = text
        var ids: [String] = []
        for candidate in candidates {
            guard let id = await loot.add(kind: candidate.kind, source: source, value: candidate.value) else {
                continue
            }
            ids.append(id)
            result = result.replacingOccurrences(of: candidate.value, with: "[loot:\(id)]")
        }
        return (result, ids)
    }
}
