import BatonPassCore
import SwiftUI

@main
struct BatonPassApp: App {
    var body: some Scene {
        WindowGroup { SetupView() }
    }
}

/// Setup only. Phase 1 is send-only, so there is no clipboard UI here.
///
/// Receiving on iOS would need a foreground fetch: the pasteboard cannot be
/// written from the background, so an agent like the desktop ones is not possible.
/// That is T11, not this.
struct SetupView: View {
    @State private var relayHost = Config.relayHost
    @State private var group = Config.group
    @State private var senderId = String(Config.senderId)
    @State private var keyHex = ""
    @State private var hasKey = Config.hasKey
    @State private var status: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Relay") {
                    TextField("100.64.0.20:4000", text: $relayHost)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("group", text: $group)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("sender id", text: $senderId)
                        .keyboardType(.numberPad)
                }

                Section {
                    if hasKey {
                        Label("Key stored on this device", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Button("Replace key", role: .destructive) { hasKey = false }
                    } else {
                        SecureField("64 hex characters", text: $keyHex)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Import key") { importKey() }
                            .disabled(keyHex.count != 64)
                    }
                } header: {
                    Text("Group key")
                } footer: {
                    Text("Type the key in by hand from a device that already has it. "
                         + "Never send it through BatonPass: it would be encrypted under "
                         + "the old key and delivered to every enrolled device.")
                }

                Section("Shortcut") {
                    Text("""
                    Shortcuts → new shortcut:
                      1. Get Clipboard
                      2. Text  ← required, or a code like 012345 can arrive as a number
                      3. Send to BatonPass

                    Settings → Accessibility → Touch → Back Tap → Double Tap → that shortcut.
                    """)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }

                if let status {
                    Section { Text(status).font(.footnote) }
                }
            }
            .navigationTitle("BatonPass")
            .onChange(of: relayHost) { _, v in Config.relayHost = v.trimmingCharacters(in: .whitespaces) }
            .onChange(of: group) { _, v in Config.group = v.trimmingCharacters(in: .whitespaces) }
            .onChange(of: senderId) { _, v in if let n = UInt32(v) { Config.senderId = n } }
        }
    }

    private func importKey() {
        do {
            try Config.importKey(hex: keyHex)
            keyHex = ""
            hasKey = true
            status = "Key imported."
        } catch {
            status = "That is not a valid 64-character key."
        }
    }
}
