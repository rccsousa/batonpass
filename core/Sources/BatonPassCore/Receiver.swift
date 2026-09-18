import CryptoKit
import Foundation

/// SPEC.md §4 step ordering and §5 replay defence.
///
/// The ordering here is normative, not an optimisation target. An adversarial
/// review found real bugs in steps 1, 5 and 6; each fix is marked.
public final class Receiver {
    public struct DedupEntry {
        public let expiresAtMs: UInt64
    }

    private let key: SymmetricKey
    private var currentEpoch: UInt32
    private var cache: [String: DedupEntry] = [:]
    private var acceptanceCounter: UInt64
    private var tripped = false

    /// 4096 covers the 120-second acceptance window many times over at this
    /// system's traffic. Fixed, not a growth target.
    private let capacity: Int
    private let freshnessMs: UInt64 = 60_000

    /// Persists the dedup entry. Must return only after the entry is durable,
    /// because the clipboard write happens after it returns.
    private let persist: (String, UInt64, UInt64) throws -> Void

    public init(key: SymmetricKey, epoch: UInt32, capacity: Int = 4096,
         acceptanceCounter: UInt64 = 0,
         persist: @escaping (String, UInt64, UInt64) throws -> Void = { _, _, _ in }) {
        self.key = key
        self.currentEpoch = epoch
        self.capacity = capacity
        self.acceptanceCounter = acceptanceCounter
        self.persist = persist
    }

    /// Returns the plaintext to write to the clipboard, or throws.
    /// The caller writes the clipboard only on success — never before.
    public func accept(frame: Data, nowMs: UInt64) throws -> Data {
        if tripped { throw Envelope.Failure.replay }

        // Steps 1-2: length and version, before any allocation or decryption.
        guard frame.count >= Envelope.minFrame else { throw Envelope.Failure.tooShort }
        guard frame.count <= Envelope.maxFrame else { throw Envelope.Failure.tooLong }
        guard frame.first == Envelope.version else { throw Envelope.Failure.badVersion }

        // Step 3: epoch, on the unauthenticated header. Exactly one epoch is live;
        // adding a rollover grace period would make this attacker-controlled key
        // selection, so it stays strict.
        let peeked = Envelope.decodeHeader(frame)
        guard peeked.epoch == currentEpoch else { throw Envelope.Failure.wrongEpoch }

        // Step 4: authenticate. Nothing below this line runs on unauthenticated input.
        let (header, plaintext) = try Envelope.open(key: key, frame: frame)

        // Step 5: freshness. Two unsigned comparisons, never `now - timestamp` —
        // timestamps ahead of now are legal and that subtraction underflows,
        // which trapped Swift on a frame 1 ms ahead.
        if header.timestampMs > nowMs + freshnessMs { throw Envelope.Failure.stale }
        if header.timestampMs + freshnessMs < nowMs { throw Envelope.Failure.stale }

        // Step 6: dedup.
        let dedupKey = Self.dedupKey(header)
        sweep(nowMs: nowMs)
        if cache[dedupKey] != nil { throw Envelope.Failure.replay }

        // Reject rather than evict. Evicting a still-valid entry under pressure is
        // exactly how the replay window would reopen.
        if cache.count >= capacity { throw Envelope.Failure.cacheFull }

        // Retention keyed to the LATER of acceptance and the frame timestamp. Using
        // acceptance time alone let a frame from a clock-ahead sender outlive its own
        // dedup entry, which was a demonstrated replay.
        let expiry = max(nowMs, header.timestampMs) + freshnessMs

        // Step 7: persist, THEN the caller writes the clipboard. A crash between the
        // two may lose a delivery; it must never permit a duplicate one.
        acceptanceCounter += 1
        try persist(dedupKey, expiry, acceptanceCounter)
        cache[dedupKey] = DedupEntry(expiresAtMs: expiry)

        return plaintext
    }

    /// Fail closed on clock rollback. Recovery is an explicit operator action, not a
    /// timer: `resume()` clears the trip and flushes the cache, since entries dated
    /// under a bad clock cannot be trusted.
    public func noteClockRollback() { tripped = true }

    public func resume() {
        tripped = false
        cache.removeAll()
    }

    public var isTripped: Bool { tripped }
    public var cacheCount: Int { cache.count }

    public func rekey(epoch: UInt32) {
        currentEpoch = epoch
        cache.removeAll()
    }

    private func sweep(nowMs: UInt64) {
        cache = cache.filter { $0.value.expiresAtMs > nowMs }
    }

    private static func dedupKey(_ h: Envelope.Header) -> String {
        "\(h.epoch):\(h.senderId):\(h.eventId.map { String(format: "%02x", $0) }.joined())"
    }
}
