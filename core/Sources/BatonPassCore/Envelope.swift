import CryptoKit
import Foundation

/// BatonPass envelope v1.1. See crypto/SPEC.md — that document is normative.
public enum Envelope {
    public static let version: UInt8 = 0x01
    public static let headerSize = 33
    public static let nonceSize = 12
    public static let tagSize = 16
    public static let maxPlaintext = 65_536

    /// 61, not 49. SPEC v1.0 stated 49 by dropping the nonce from the sum; frames
    /// of 49-60 then produced a negative ciphertext length and aborted the process.
    public static let minFrame = headerSize + nonceSize + tagSize
    public static let maxFrame = headerSize + maxPlaintext + nonceSize + tagSize

    public struct Header: Equatable {
        public var epoch: UInt32
        public var eventId: Data
        public var senderId: UInt32
        public var timestampMs: UInt64

        public init(epoch: UInt32, eventId: Data, senderId: UInt32, timestampMs: UInt64) {
            self.epoch = epoch
            self.eventId = eventId
            self.senderId = senderId
            self.timestampMs = timestampMs
        }
    }

    public enum Failure: Error, Equatable {
        case tooShort, tooLong, badVersion, wrongEpoch, authFailed
        case stale, replay, cacheFull, randomFailure
    }

    public static func encode(_ h: Header) -> Data {
        var out = Data([version])
        out.append(be32(h.epoch))
        out.append(h.eventId)
        out.append(be32(h.senderId))
        out.append(be64(h.timestampMs))
        precondition(out.count == headerSize)
        return out
    }

    public static func decodeHeader(_ frame: Data) -> Header {
        let b = [UInt8](frame.prefix(headerSize))
        return Header(
            epoch: read32(b, 1),
            eventId: Data(b[5..<21]),
            senderId: read32(b, 21),
            timestampMs: read64(b, 25)
        )
    }

    /// The AAD is the header bytes verbatim, never a formatted string. There are no
    /// separators or integer formatting for two languages to disagree about.
    public static func seal(key: SymmetricKey, header: Header, nonce: Data, plaintext: Data) throws -> Data {
        let aad = encode(header)
        let box = try ChaChaPoly.seal(plaintext, using: key,
                                      nonce: try ChaChaPoly.Nonce(data: nonce),
                                      authenticating: aad)
        return aad + nonce + box.ciphertext + box.tag
    }

    public static func open(key: SymmetricKey, frame: Data) throws -> (Header, Data) {
        guard frame.count >= minFrame else { throw Failure.tooShort }
        guard frame.count <= maxFrame else { throw Failure.tooLong }
        guard frame.first == version else { throw Failure.badVersion }

        let bytes = [UInt8](frame)
        let aad = Data(bytes[0..<headerSize])
        let nonce = Data(bytes[headerSize..<(headerSize + nonceSize)])
        let ct = Data(bytes[(headerSize + nonceSize)..<(bytes.count - tagSize)])
        let tag = Data(bytes[(bytes.count - tagSize)...])

        do {
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                               ciphertext: ct, tag: tag)
            let pt = try ChaChaPoly.open(box, using: key, authenticating: aad)
            return (decodeHeader(frame), pt)
        } catch {
            throw Failure.authFailed
        }
    }

    /// Aborts rather than returning a zero-filled buffer. A repeated nonce under one
    /// key yields P1 XOR P2 and recovery of the Poly1305 key, which turns the
    /// untrusted relay from a replayer into a forger.
    public static func randomBytes(_ count: Int) throws -> Data {
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, count, buf.baseAddress!)
        }
        guard status == errSecSuccess else { throw Failure.randomFailure }
        return out
    }

    private static func be32(_ v: UInt32) -> Data {
        Data([UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)])
    }

    private static func be64(_ v: UInt64) -> Data {
        Data((0..<8).reversed().map { UInt8(v >> (UInt64($0) * 8) & 0xff) })
    }

    private static func read32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
    }

    private static func read64(_ b: [UInt8], _ o: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 << 8 | UInt64(b[o + $1]) }
    }
}
