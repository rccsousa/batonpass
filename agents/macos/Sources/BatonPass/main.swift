import BatonPassCore
import AppKit
import CryptoKit
import Foundation

// LaunchAgent, never a LaunchDaemon: a daemon runs outside the user session and
// cannot reach the clipboard.

// Unbuffered: this runs under launchd with stdout to a file, where the default
// full buffering hides everything until exit.
setvbuf(stdout, nil, _IONBF, 0)

let args = CommandLine.arguments

func die(_ message: String, _ code: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

if args.contains("--verify-vectors") {
    let path = args.last ?? "../../crypto/vectors.json"
    exit(VectorRunner.run(path: path) ? 0 : 1)
}

// Prints the key once, for out-of-band transport to the other devices. SPEC.md §6
// forbids sending it over BatonPass itself: that would encrypt it under the old
// key and hand it to the device being revoked.
if args.contains("--generate-key") {
    guard let key = try? Envelope.randomBytes(32) else { die("CSPRNG failed") }
    do { try Keyring.store(key) } catch { die("keychain write failed: \(error)") }
    print(VectorRunner.hex(key))
    FileHandle.standardError.write(Data("""

    Stored in the login keychain. Type it into the other devices by hand.
    Never send it through BatonPass, and never paste it into a page the relay serves.

    """.utf8))
    exit(0)
}

if let i = args.firstIndex(of: "--import-key"), i + 1 < args.count {
    let hex = args[i + 1].trimmingCharacters(in: .whitespacesAndNewlines)
    guard hex.count == 64 else { die("key must be 64 hex characters") }
    let key = VectorRunner.unhex(hex)
    guard key.count == 32 else { die("key must be 64 hex characters") }
    do { try Keyring.store(key) } catch { die("keychain write failed: \(error)") }
    print("imported")
    exit(0)
}

let vars = ProcessInfo.processInfo.environment

// Keychain is the real source. The variable exists for tests and for the
// end-to-end harness, which runs two agents with different sender ids.
let keyData: Data
if let hex = vars["BATONPASS_KEY"], hex.count == 64 {
    keyData = VectorRunner.unhex(hex)
} else {
    do {
        keyData = try Keyring.load()
    } catch Keyring.Failure.notFound {
        die("""
        batonpass-macos: no group key

          batonpass --generate-key        create one and print it (first device)
          batonpass --import-key <hex>    import a key from another device

        """)
    } catch {
        die("batonpass: keychain read failed: \(error)")
    }
}

let relay = vars["BATONPASS_RELAY"] ?? "ws://127.0.0.1:4000/socket/websocket?vsn=2.0.0"
let group = vars["BATONPASS_GROUP"] ?? "home"
let sender = UInt32(vars["BATONPASS_SENDER"] ?? "1") ?? 1

guard let url = URL(string: relay) else { die("batonpass: bad relay URL") }

let agent = Agent(
    key: SymmetricKey(data: keyData),
    epoch: UInt32(vars["BATONPASS_EPOCH"] ?? "1") ?? 1,
    senderId: sender,
    relayURL: url,
    group: group
)

// --send-once pushes one item and exits. Used for testing the wire without
// running two clipboard watchers against the same pasteboard.
if let i = args.firstIndex(of: "--send-once"), i + 1 < args.count {
    let text = args[i + 1]
    agent.sendOnceThenExit(text)
    RunLoop.main.run()
}

print("batonpass-macos: relay \(relay) group \(group) sender \(sender)")
agent.start()
RunLoop.main.run()
