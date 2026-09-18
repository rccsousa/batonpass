import CryptoKit
import XCTest
@testable import BatonPassCore

/// SPEC.md is explicit that vectors.json exercises §4 step 4 only. Steps 3, 5, 6
/// and 7 depend on receiver state and wall-clock time, and every bug the
/// adversarial review found lived in exactly those steps. This is that coverage.
final class ReceiverTests: XCTestCase {
    let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
    let now: UInt64 = 1_757_600_000_000

    private func frame(epoch: UInt32 = 1, sender: UInt32 = 7,
                       ts: UInt64? = nil, eventId: UInt8 = 0xaa,
                       text: String = "secret") throws -> Data {
        let header = Envelope.Header(
            epoch: epoch,
            eventId: Data(repeating: eventId, count: 16),
            senderId: sender,
            timestampMs: ts ?? now
        )
        return try Envelope.seal(key: key, header: header,
                                 nonce: try Envelope.randomBytes(12),
                                 plaintext: Data(text.utf8))
    }

    private func receiver(capacity: Int = 4096) -> Receiver {
        Receiver(key: key, epoch: 1, capacity: capacity)
    }

    func testAcceptsAFreshFrame() throws {
        let r = receiver()
        let pt = try r.accept(frame: try frame(), nowMs: now)
        XCTAssertEqual(String(data: pt, encoding: .utf8), "secret")
    }

    func testRejectsAnExactReplay() throws {
        let r = receiver()
        let f = try frame()
        _ = try r.accept(frame: f, nowMs: now)
        XCTAssertThrowsError(try r.accept(frame: f, nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .replay)
        }
    }

    /// F1: the demonstrated replay. Sender's clock 45 s ahead; the relay holds the
    /// frame and re-sends at +61 s. Retention keyed to acceptance time alone let
    /// the dedup entry expire while the frame was still fresh.
    func testReplayAcrossClockSkewIsRejected() throws {
        let r = receiver()
        let skewed = now + 45_000
        let f = try frame(ts: skewed)

        _ = try r.accept(frame: f, nowMs: now)

        XCTAssertThrowsError(try r.accept(frame: f, nowMs: now + 61_000)) {
            XCTAssertEqual($0 as? Envelope.Failure, .replay,
                           "entry must live until max(now, timestamp) + 60s")
        }
    }

    /// F3: timestamps ahead of now are legal, so unsigned `now - timestamp`
    /// underflows. Swift trapped on a frame 1 ms ahead.
    func testFrameOneMillisecondAheadIsAccepted() throws {
        let r = receiver()
        let pt = try r.accept(frame: try frame(ts: now + 1), nowMs: now)
        XCTAssertEqual(String(data: pt, encoding: .utf8), "secret")
    }

    func testFrameWithinTheAheadWindowIsAccepted() throws {
        let r = receiver()
        XCTAssertNoThrow(try r.accept(frame: try frame(ts: now + 59_000), nowMs: now))
    }

    func testFrameTooFarAheadIsRejected() throws {
        let r = receiver()
        XCTAssertThrowsError(try r.accept(frame: try frame(ts: now + 61_000), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .stale)
        }
    }

    func testFrameTooOldIsRejected() throws {
        let r = receiver()
        XCTAssertThrowsError(try r.accept(frame: try frame(ts: now - 61_000), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .stale)
        }
    }

    func testWrongEpochIsRejectedBeforeDecryption() throws {
        let r = receiver()
        XCTAssertThrowsError(try r.accept(frame: try frame(epoch: 2), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .wrongEpoch)
        }
    }

    /// Reject rather than evict: evicting a still-valid entry reopens the window.
    func testCacheFullRejectsRatherThanEvicting() throws {
        let r = receiver(capacity: 2)
        _ = try r.accept(frame: try frame(eventId: 0x01), nowMs: now)
        _ = try r.accept(frame: try frame(eventId: 0x02), nowMs: now)

        XCTAssertThrowsError(try r.accept(frame: try frame(eventId: 0x03), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .cacheFull)
        }
        XCTAssertEqual(r.cacheCount, 2, "a still-valid entry must not be evicted")
    }

    func testExpiredEntriesAreSweptSoTheCacheRecovers() throws {
        let r = receiver(capacity: 2)
        _ = try r.accept(frame: try frame(eventId: 0x01), nowMs: now)
        _ = try r.accept(frame: try frame(eventId: 0x02), nowMs: now)

        let later = now + 120_000
        XCTAssertNoThrow(try r.accept(frame: try frame(ts: later, eventId: 0x03), nowMs: later))
    }

    /// Persist must complete before the caller writes the clipboard: a crash may
    /// lose a delivery but must never permit a duplicate one.
    func testPersistHappensBeforeTheValueIsReturned() throws {
        var persisted: [String] = []
        let r = Receiver(key: key, epoch: 1, persist: { k, _, _ in persisted.append(k) })

        _ = try r.accept(frame: try frame(), nowMs: now)
        XCTAssertEqual(persisted.count, 1)
    }

    func testAFailedPersistRejectsTheFrame() throws {
        struct DiskFull: Error {}
        let r = Receiver(key: key, epoch: 1, persist: { _, _, _ in throw DiskFull() })

        XCTAssertThrowsError(try r.accept(frame: try frame(), nowMs: now))
        XCTAssertEqual(r.cacheCount, 0, "a frame that could not be recorded must not be accepted")
    }

    func testClockRollbackFailsClosedUntilAnExplicitResume() throws {
        let r = receiver()
        r.noteClockRollback()

        XCTAssertThrowsError(try r.accept(frame: try frame(), nowMs: now))
        XCTAssertTrue(r.isTripped)

        r.resume()
        XCTAssertNoThrow(try r.accept(frame: try frame(), nowMs: now))
    }

    func testRekeyClearsTheCache() throws {
        let r = receiver()
        _ = try r.accept(frame: try frame(), nowMs: now)
        r.rekey(epoch: 2)
        XCTAssertEqual(r.cacheCount, 0)
    }

    func testShortAndOversizeFramesAreRejected() throws {
        let r = receiver()
        XCTAssertThrowsError(try r.accept(frame: Data(repeating: 1, count: 60), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .tooShort)
        }
        XCTAssertThrowsError(try r.accept(frame: Data(repeating: 1, count: 49), nowMs: now)) {
            XCTAssertEqual($0 as? Envelope.Failure, .tooShort)
        }
    }
}
