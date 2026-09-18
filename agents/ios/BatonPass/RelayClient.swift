import BatonPassCore
import Foundation

/// Connects, joins, pushes one frame, waits for it to leave, disconnects.
///
/// Deliberately not a long-lived connection: the intent is invoked from a Back
/// Tap and the process may be cold-started and torn down around a single send.
/// Holding a socket open across that is not something iOS guarantees.
enum RelayClient {
    static func send(frame: Data, timeout: TimeInterval = 10) async throws {
        guard let url = Config.relayURL else {
            throw SendError.relayFailed("no relay configured")
        }

        let socket = PhoenixSocket(url: url, topic: "clipboard:\(Config.group)")

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            var finished = false
            let finish: (Error?) -> Void = { error in
                guard !finished else { return }
                finished = true
                socket.disconnect()
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            }

            socket.onStateChange = { state in
                if state == "connected" {
                    socket.push(frame: frame) { error in
                        finish(error.map { SendError.relayFailed($0.localizedDescription) })
                    }
                } else if state.hasPrefix("closed") || state.hasPrefix("receive failed") {
                    finish(SendError.relayFailed(state))
                }
            }

            socket.connect()

            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                finish(SendError.relayFailed("timed out after \(Int(timeout))s"))
            }
        }
    }
}
