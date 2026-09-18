import BatonPassCore
import AppKit
import CryptoKit
import Foundation

/// The macOS clipboard agent. T8.
final class Agent {
    private let key: SymmetricKey
    private let epoch: UInt32
    private let senderId: UInt32
    private let receiver: Receiver
    private let socket: PhoenixSocket

    private var lastChangeCount: Int
    private var lastWrittenHash: Int?
    private var paused = false

    init(key: SymmetricKey, epoch: UInt32, senderId: UInt32, relayURL: URL, group: String) {
        self.key = key
        self.epoch = epoch
        self.senderId = senderId
        self.receiver = Receiver(key: key, epoch: epoch)
        self.socket = PhoenixSocket(url: relayURL, topic: "clipboard:\(group)")
        self.lastChangeCount = Clipboard.changeCount
    }

    func start() {
        socket.onStateChange = { print("relay: \($0)") }
        socket.onFrame = { [weak self] frame in self?.handle(frame: frame) }
        socket.connect()

        Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    func sendOnceThenExit(_ text: String) {
        socket.onStateChange = { state in
            print("relay: \(state)")
            if state == "connected" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                    self.send(text)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { exit(0) }
                }
            }
        }
        socket.connect()
    }

    func pause() { paused = true }
    func resume() { paused = false }

    private func poll() {
        guard !paused else { return }

        let current = Clipboard.changeCount
        guard current != lastChangeCount else { return }
        lastChangeCount = current

        // Universal Clipboard delivers iPhone copies here independently. Re-sending
        // one would duplicate a delivery the iPhone already made directly, and the
        // envelope dedup cannot catch it: different sender, different event id,
        // same content. This check must come first.
        guard let text = Clipboard.readLocalString() else { return }

        // Our own write arriving back as a change notification.
        if let last = lastWrittenHash, last == text.hashValue { return }

        send(text)
    }

    private func send(_ text: String) {
        let plaintext = Data(text.utf8)
        guard plaintext.count <= Envelope.maxPlaintext else {
            print("batonpass: item too large (\(plaintext.count)B), not sent")
            return
        }

        do {
            let header = Envelope.Header(
                epoch: epoch,
                eventId: try Envelope.randomBytes(16),
                senderId: senderId,
                timestampMs: UInt64(Date().timeIntervalSince1970 * 1000)
            )
            let frame = try Envelope.seal(key: key, header: header,
                                          nonce: try Envelope.randomBytes(12),
                                          plaintext: plaintext)
            socket.push(frame: frame) { error in
                if let error {
                    print("batonpass: send failed (\(plaintext.count)B): \(error.localizedDescription)")
                } else {
                    print("batonpass: sent \(plaintext.count)B")
                }
            }
        } catch Envelope.Failure.randomFailure {
            // The one failure that lets the relay forge rather than merely replay.
            FileHandle.standardError.write(Data("batonpass: CSPRNG failed, refusing to send\n".utf8))
        } catch {
            print("batonpass: send failed")
        }
    }

    private func handle(frame: Data) {
        guard !paused else { return }

        do {
            let nowMs = UInt64(Date().timeIntervalSince1970 * 1000)
            let plaintext = try receiver.accept(frame: frame, nowMs: nowMs)
            guard let text = String(data: plaintext, encoding: .utf8) else { return }

            lastWrittenHash = text.hashValue
            Clipboard.write(text)
            lastChangeCount = Clipboard.changeCount
            print("batonpass: received \(plaintext.count)B")
        } catch {
            // Size only. Never the frame, never any slice of it.
            print("batonpass: rejected frame (\(frame.count)B): \(error)")
        }
    }
}
