import AppIntents
import BatonPassCore
import CryptoKit
import Foundation

/// The iOS send path. T5.
///
/// The text arrives as a **parameter from the Shortcut**, which does the
/// `Get Clipboard`. This app never touches `UIPasteboard` — deliberately, and it
/// is the whole reason the design works: pasteboard reads are foreground-only on
/// iOS and raise an "Allow Paste" alert, and neither applies to an app that does
/// not read the pasteboard at all.
///
/// If you are tempted to add a `UIPasteboard` call here, read
/// spikes/s1-ios-app-intent/FINDINGS.md first.
struct SendClipboardIntent: AppIntent {
    static var title: LocalizedStringResource = "Send to BatonPass"
    static var description = IntentDescription(
        "Encrypts text and sends it to your other BatonPass devices."
    )

    /// Background execution: no app switch, which is the point of the Back Tap flow.
    static var openAppWhenRun: Bool = false

    @Parameter(title: "Text")
    var text: String

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        // Shortcuts will coerce other types into a String parameter rather than
        // refuse them, which is how a TOTP code like "012345" could arrive as the
        // number 12345. The shortcut must use an explicit Text action; this is the
        // last line of defence, not the only one.
        let payload = text

        guard !payload.isEmpty else {
            throw $text.needsValueError("Nothing to send.")
        }

        let plaintext = Data(payload.utf8)
        guard plaintext.count <= Envelope.maxPlaintext else {
            throw SendError.tooLarge(plaintext.count)
        }

        let key = try Config.loadKey()
        let frame = try Envelope.seal(
            key: key,
            header: Envelope.Header(
                epoch: Config.epoch,
                eventId: try Envelope.randomBytes(16),
                senderId: Config.senderId,
                timestampMs: UInt64(Date().timeIntervalSince1970 * 1000)
            ),
            nonce: try Envelope.randomBytes(12),
            plaintext: plaintext
        )

        // Awaited, not fire-and-forget. An intent that returns success before the
        // send completes reports success for deliveries that never happened.
        try await RelayClient.send(frame: frame)

        return .result(value: "Sent \(plaintext.count) bytes")
    }
}

enum SendError: Error, CustomLocalizedStringResourceConvertible {
    case tooLarge(Int)
    case noKey
    case relayFailed(String)

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .tooLarge(let n):
            return "Too large to send (\(n) bytes, limit \(Envelope.maxPlaintext))."
        case .noKey:
            return "No BatonPass key on this device. Open the app to import one."
        case .relayFailed(let why):
            return "Could not reach the relay: \(why)"
        }
    }
}

struct BatonPassShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: SendClipboardIntent(),
            phrases: ["Send to \(.applicationName)"],
            shortTitle: "Send to BatonPass",
            systemImageName: "doc.on.clipboard"
        )
    }
}
