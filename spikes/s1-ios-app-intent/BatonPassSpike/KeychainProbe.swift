import Foundation
import Security

/// Answers the S1 question "which Keychain accessibility class is readable from a
/// background intent while the device is locked" — the group key (T1) has to live
/// in one of these, so the wrong choice fails silently at 3am, not in testing.
enum KeychainProbe {
    static let classes: [(name: String, accessible: CFString)] = [
        ("WhenUnlockedThisDeviceOnly", kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ("AfterFirstUnlockThisDeviceOnly", kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
    ]

    static func seed() {
        for entry in classes {
            let account = "probe.\(entry.name)"
            SecItemDelete(baseQuery(account: account) as CFDictionary)
            var attributes = baseQuery(account: account)
            attributes[kSecValueData as String] = Data("ok".utf8)
            attributes[kSecAttrAccessible as String] = entry.accessible
            let status = SecItemAdd(attributes as CFDictionary, nil)
            SpikeLog.append("keychain seed \(entry.name) status=\(status)")
        }
    }

    /// Returns one line per class, e.g. "WhenUnlockedThisDeviceOnly=ok".
    /// `-25308` is errSecInteractionNotAllowed — the locked-device answer.
    static func readAll() -> String {
        classes.map { entry in
            var query = baseQuery(account: "probe.\(entry.name)")
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            let outcome = status == errSecSuccess ? "ok" : "status=\(status)"
            return "\(entry.name)=\(outcome)"
        }
        .joined(separator: " ")
    }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "co.subvisual.batonpass.spike",
            kSecAttrAccount as String: account,
        ]
    }
}
