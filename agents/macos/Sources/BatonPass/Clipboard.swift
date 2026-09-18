import BatonPassCore
import AppKit
import Foundation

/// macOS clipboard access. See spikes/s5-universal-clipboard/FINDINGS.md for the
/// evidence behind the two Universal Clipboard rules below.
enum Clipboard {
    /// Undocumented: this type appears zero times in the macOS SDK. Observed on
    /// 3/3 Universal Clipboard deliveries and 0/6 local copies. It fails OPEN if a
    /// future macOS drops it, which is why `sawRemoteMarker` exists.
    static let remoteMarker = NSPasteboard.PasteboardType("com.apple.is-remote-clipboard")

    private(set) static var sawRemoteMarker = false

    static var changeCount: Int { NSPasteboard.general.changeCount }

    /// Returns nil when the current item came from Universal Clipboard.
    ///
    /// The marker carries a zero-byte value, so this must test membership in the
    /// type list. Testing the value's truthiness fails open.
    static func readLocalString() -> String? {
        let pb = NSPasteboard.general
        guard let item = pb.pasteboardItems?.first else { return nil }

        if item.types.contains(remoteMarker) {
            sawRemoteMarker = true
            return nil
        }

        return pb.string(forType: .string)
    }

    /// `.currentHostOnly` stops Universal Clipboard re-exporting our write to the
    /// iPhone. S5 saw it leak once in five trials, so it is a second line of
    /// defence, never the only one.
    static func write(_ text: String) {
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: [.currentHostOnly])
        pb.setString(text, forType: .string)
    }
}
