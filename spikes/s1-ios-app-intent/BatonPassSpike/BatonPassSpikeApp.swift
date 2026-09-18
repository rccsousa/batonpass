import SwiftUI

@main
struct BatonPassSpikeApp: App {
    var body: some Scene {
        WindowGroup {
            SpikeView()
        }
    }
}

struct SpikeView: View {
    @State private var endpoint = Config.endpoint
    @State private var probeText = "012345"
    @State private var entries: [SpikeLogEntry] = SpikeLog.entries()
    @State private var busy = false
    @State private var keychain = "not read"

    var body: some View {
        NavigationStack {
            Form {
                Section("Receiver") {
                    TextField("http://host:port/path", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .onSubmit { Config.endpoint = endpoint }
                    Button("Save endpoint") { Config.endpoint = endpoint }
                }

                Section("Keychain probe") {
                    Text(keychain).font(.system(.footnote, design: .monospaced))
                    Button("Seed keychain items") {
                        KeychainProbe.seed()
                        keychain = KeychainProbe.readAll()
                        entries = SpikeLog.entries()
                    }
                    Button("Read now") { keychain = KeychainProbe.readAll() }
                }

                Section("Manual probe") {
                    TextField("text to send", text: $probeText)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button(busy ? "Sending…" : "Send (same path as the intent)") {
                        Task { await probe() }
                    }
                    .disabled(busy)
                    Text("This app never reads the clipboard. Typed text only.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Log") {
                    if entries.isEmpty {
                        Text("empty").foregroundStyle(.secondary)
                    }
                    ForEach(entries.reversed()) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.at.formatted(date: .omitted, time: .standard))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Text(entry.line).font(.system(.footnote, design: .monospaced))
                        }
                    }
                }

                Section {
                    Button("Refresh log") { entries = SpikeLog.entries() }
                    Button("Clear log", role: .destructive) {
                        SpikeLog.clear()
                        entries = []
                    }
                }

                Section {
                    Text("S1 spike build. Sends PLAINTEXT over HTTP. Not for real secrets.")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
            .navigationTitle("BatonPass S1")
        }
        .onAppear {
            entries = SpikeLog.entries()
            keychain = KeychainProbe.readAll()
        }
    }

    private func probe() async {
        busy = true
        defer {
            busy = false
            entries = SpikeLog.entries()
        }
        Config.endpoint = endpoint
        do {
            let reply = try await Sender.post(text: probeText, to: endpoint)
            SpikeLog.append("probe ok reply=\(reply.prefix(120))")
        } catch {
            SpikeLog.append("probe FAIL \(error.localizedDescription)")
        }
    }
}
