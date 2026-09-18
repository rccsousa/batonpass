import BatonPassCore
import CryptoKit
import Foundation

/// Device configuration. The key lives in the Keychain; everything else is a
/// user default, because none of it is secret.
enum Config {
    private static let defaults = UserDefaults.standard

    static var relayHost: String {
        get { defaults.string(forKey: "relayHost") ?? "" }
        set { defaults.set(newValue, forKey: "relayHost") }
    }

    static var group: String {
        get { defaults.string(forKey: "group") ?? "home" }
        set { defaults.set(newValue, forKey: "group") }
    }

    static var senderId: UInt32 {
        get {
            let stored = UInt32(defaults.integer(forKey: "senderId"))
            return stored == 0 ? 3 : stored
        }
        set { defaults.set(Int(newValue), forKey: "senderId") }
    }

    static var epoch: UInt32 {
        get {
            let stored = UInt32(defaults.integer(forKey: "epoch"))
            return stored == 0 ? 1 : stored
        }
        set { defaults.set(Int(newValue), forKey: "epoch") }
    }

    static var relayURL: URL? {
        guard !relayHost.isEmpty else { return nil }
        return URL(string: "ws://\(relayHost)/socket/websocket?vsn=2.0.0")
    }

    static func loadKey() throws -> SymmetricKey {
        do {
            return SymmetricKey(data: try Keyring.load())
        } catch {
            throw SendError.noKey
        }
    }

    static func importKey(hex: String) throws {
        let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 64 else { throw SendError.noKey }
        let data = VectorRunner.unhex(trimmed)
        guard data.count == 32 else { throw SendError.noKey }
        try Keyring.store(data)
    }

    static var hasKey: Bool { (try? Keyring.load()) != nil }
}
