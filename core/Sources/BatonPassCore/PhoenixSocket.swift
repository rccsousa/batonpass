import Foundation

/// Minimal Phoenix channel client, binary frames only.
///
/// Phoenix's V2 serializer frames a binary push as a fixed header of five
/// length bytes followed by the four string fields and then the payload. There
/// is no Swift client for this, hence the hand-rolled encoder.
public final class PhoenixSocket: NSObject {
    public enum Kind: UInt8 { case push = 0, reply = 1, broadcast = 2 }

    public enum Failure: LocalizedError {
        case notConnected
        public var errorDescription: String? { "relay socket is not connected" }
    }

    private var task: URLSessionWebSocketTask?
    private var session: URLSession!
    private let url: URL
    private let topic: String
    private var ref = 0
    private let joinRef = "1"

    /// A clipboard agent that silently stops reconnecting is worse than one that
    /// crashes: it keeps reporting "sent" while nothing leaves the machine.
    private var reconnectDelay: TimeInterval = 1
    private let maxReconnectDelay: TimeInterval = 30
    private var reconnecting = false
    private var intentionallyClosed = false
    private let queue = DispatchQueue(label: "batonpass.socket")

    public private(set) var isConnected = false

    public var onFrame: ((Data) -> Void)?
    public var onStateChange: ((String) -> Void)?

    public init(url: URL, topic: String) {
        self.url = url
        self.topic = topic
        super.init()
        session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }

    public func connect() {
        intentionallyClosed = false
        openSocket()
    }

    private func openSocket() {
        // Drop the reference before cancelling. The cancel delivers didCloseWith and a
        // "cancelled" receive failure, and both are keyed off `task` identity to tell
        // our own teardown from a real drop. Leaving it set made every reconnect
        // schedule another reconnect, which then cancelled the socket it had opened.
        let stale = task
        task = nil
        stale?.cancel(with: .goingAway, reason: nil)

        let fresh = session.webSocketTask(with: url)
        task = fresh
        fresh.resume()
        receive(on: fresh)
        // join() is sent from didOpen: joining before the socket is open leaves the
        // channel unjoined after a reconnect, so frames are pushed into a topic
        // nobody is subscribed to.
    }

    public func disconnect() {
        intentionallyClosed = true
        isConnected = false
        let stale = task
        task = nil
        stale?.cancel(with: .goingAway, reason: nil)
    }

    /// Exponential backoff, reset on a successful open. Guarded so a failed send
    /// and a closed socket arriving together schedule one retry, not two.
    private func scheduleReconnect(_ why: String) {
        guard !intentionallyClosed, !reconnecting else { return }
        reconnecting = true
        isConnected = false

        let delay = reconnectDelay
        onStateChange?("disconnected (\(why)); retrying in \(Int(delay))s")

        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, !self.intentionallyClosed else { return }
            self.reconnecting = false
            self.reconnectDelay = min(self.reconnectDelay * 2, self.maxReconnectDelay)
            self.openSocket()
        }
    }

    private func nextRef() -> String {
        ref += 1
        return String(ref)
    }

    private func join() {
        // The join itself is JSON; only clipboard frames are binary.
        let msg = "[\"\(joinRef)\",\"\(nextRef())\",\"\(topic)\",\"phx_join\",{}]"
        task?.send(.string(msg)) { [weak self] error in
            if let error { self?.onStateChange?("join failed: \(error.localizedDescription)") }
        }
    }

    public func push(frame: Data, completion: ((Error?) -> Void)? = nil) {
        guard let task, isConnected else {
            completion?(Failure.notConnected)
            scheduleReconnect("send attempted while disconnected")
            return
        }
        let encoded = encodeBinary(event: "frame", payload: frame)
        task.send(.data(encoded)) { [weak self] error in
            if let error {
                self?.onStateChange?("send failed: \(error.localizedDescription)")
                self?.scheduleReconnect("send failed")
            }
            completion?(error)
        }
    }

    private func encodeBinary(event: String, payload: Data) -> Data {
        let refStr = nextRef()
        var out = Data([Kind.push.rawValue,
                        UInt8(joinRef.utf8.count),
                        UInt8(refStr.utf8.count),
                        UInt8(topic.utf8.count),
                        UInt8(event.utf8.count)])
        out.append(contentsOf: joinRef.utf8)
        out.append(contentsOf: refStr.utf8)
        out.append(contentsOf: topic.utf8)
        out.append(contentsOf: event.utf8)
        out.append(payload)
        return out
    }

    /// Phoenix V2 uses three different binary header shapes and they are not
    /// interchangeable. Verified against
    /// deps/phoenix/lib/phoenix/socket/serializers/v2_json_serializer.ex:
    ///
    ///   broadcast (2): kind, topic_size, event_size                       -> 3 bytes
    ///   push      (0): kind, join_ref_size, topic_size, event_size        -> 4 bytes (server -> client)
    ///   push      (0): kind, join_ref_size, ref_size, topic_size, event_size -> 5 bytes (client -> server)
    private func decodeBinary(_ data: Data) -> Data? {
        let b = [UInt8](data)
        guard let first = b.first, let kind = Kind(rawValue: first) else { return nil }

        let start: Int
        switch kind {
        case .broadcast:
            guard b.count >= 3 else { return nil }
            start = 3 + Int(b[1]) + Int(b[2])
        case .push:
            guard b.count >= 4 else { return nil }
            start = 4 + Int(b[1]) + Int(b[2]) + Int(b[3])
        case .reply:
            return nil
        }

        guard b.count > start else { return nil }
        return Data(b[start...])
    }

    private func receive(on wsTask: URLSessionWebSocketTask) {
        wsTask.receive { [weak self] result in
            guard let self, wsTask === self.task else { return }
            switch result {
            case .failure(let error):
                self.onStateChange?("receive failed: \(error.localizedDescription)")
                self.scheduleReconnect("receive failed")
            case .success(let message):
                switch message {
                case .data(let data):
                    if let frame = self.decodeBinary(data) { self.onFrame?(frame) }
                case .string:
                    break  // replies and heartbeats; nothing to do
                @unknown default:
                    break
                }
                self.receive(on: wsTask)
            }
        }
    }
}

extension PhoenixSocket: URLSessionWebSocketDelegate {
    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didOpenWithProtocol protocol: String?) {
        guard webSocketTask === task else { return }
        isConnected = true
        reconnectDelay = 1
        join()
        onStateChange?("connected")
    }

    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        guard webSocketTask === task else { return }
        onStateChange?("closed: \(closeCode.rawValue)")
        scheduleReconnect("closed \(closeCode.rawValue)")
    }
}
