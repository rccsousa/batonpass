import AppIntents
import Foundation

struct SendClipboardIntent: AppIntent {
    static var title: LocalizedStringResource = "Send Text to BatonPass"

    static var description = IntentDescription(
        "Sends text handed in by the Shortcut. The app never reads the clipboard itself."
    )

    // The S1 hypothesis in one line: run in the app's background process, never
    // foreground it. Anything that flips this to foreground invalidates the spike.
    static var openAppWhenRun: Bool = false

    @available(iOS 26.0, *)
    static var supportedModes: IntentModes { .background }

    static var isDiscoverable: Bool = true

    /// `.connectToPreviousIntentResult` is what makes `Get Clipboard` wire itself
    /// straight into this parameter when the action is added in Shortcuts.
    @Parameter(title: "Text", inputConnectionBehavior: .connectToPreviousIntentResult)
    var text: String

    static var parameterSummary: some ParameterSummary {
        Summary("Send \(\.$text) to BatonPass")
    }

    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let endpoint = Config.endpoint
        let shape = Shape(of: text)
        SpikeLog.append("start \(shape) -> \(endpoint)")
        SpikeLog.append("keychain \(KeychainProbe.readAll())")

        do {
            // Awaited, not detached. A detached POST would let this return success
            // before the network call resolved — the failure mode S1 exists to rule out.
            let reply = try await Sender.post(text: text, to: endpoint)
            SpikeLog.append("ok \(shape) reply=\(reply.prefix(120))")
            return .result(value: "sent \(shape.utf8Length) bytes")
        } catch {
            SpikeLog.append("FAIL \(shape) \(error.localizedDescription)")
            throw error
        }
    }
}

/// Describes the text without storing it. The on-device log must not become a
/// clipboard history; the receiver already has the full plaintext for this spike.
private struct Shape: CustomStringConvertible {
    let utf8Length: Int
    let characterCount: Int
    let firstCharacter: String
    let allDigits: Bool

    init(of text: String) {
        utf8Length = text.utf8.count
        characterCount = text.count
        firstCharacter = text.isEmpty ? "-" : String(text.prefix(1))
        allDigits = !text.isEmpty && text.allSatisfy(\.isNumber)
    }

    var description: String {
        "len=\(utf8Length) chars=\(characterCount) first=\(firstCharacter) digits=\(allDigits)"
    }
}
