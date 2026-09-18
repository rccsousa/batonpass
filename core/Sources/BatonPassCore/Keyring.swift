import Foundation
import Security

/// Group key storage. SPEC.md §6: Keychain on macOS, device-local and
/// non-backed-up.
public enum Keyring {
    private static let service = "batonpass"
    private static let account = "group-key"

    public enum Failure: Error { case notFound, badData, keychain(OSStatus) }

    /// `ThisDeviceOnly` is required, not stylistic: a backed-up key can be restored
    /// onto another device, and a restore can resurrect an epoch that was revoked.
    public static func store(_ key: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = key
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }

    public static func load() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { throw Failure.badData }
            return data
        case errSecItemNotFound:
            throw Failure.notFound
        default:
            throw Failure.keychain(status)
        }
    }

    public static func delete() {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ] as CFDictionary)
    }
}
