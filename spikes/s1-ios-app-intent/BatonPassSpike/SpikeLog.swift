import Foundation

struct SpikeLogEntry: Codable, Identifiable {
    var id = UUID()
    var at: Date
    var line: String
}

/// Survives process death so a background intent invocation is still inspectable
/// after the fact — the whole point of S1 is runs where no UI was ever on screen.
enum SpikeLog {
    private static let key = "batonpass.log"
    private static let limit = 200
    private static let lock = NSLock()

    static func append(_ line: String) {
        lock.lock()
        defer { lock.unlock() }
        var entries = read()
        entries.append(SpikeLogEntry(at: Date(), line: line))
        if entries.count > limit { entries.removeFirst(entries.count - limit) }
        guard let data = try? JSONEncoder().encode(entries) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }

    static func entries() -> [SpikeLogEntry] {
        lock.lock()
        defer { lock.unlock() }
        return read()
    }

    static func clear() {
        lock.lock()
        defer { lock.unlock() }
        UserDefaults.standard.removeObject(forKey: key)
    }

    private static func read() -> [SpikeLogEntry] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let entries = try? JSONDecoder().decode([SpikeLogEntry].self, from: data)
        else { return [] }
        return entries
    }
}
