import CryptoKit
import Foundation

// Reference implementation of the BatonPass v1 envelope. Generates vectors.json.
// See ../SPEC.md — that document is normative, this is the generator.

let version: UInt8 = 0x01
let headerSize = 33
let nonceSize = 12
let tagSize = 16
let maxPlaintext = 65_536
let minFrame = headerSize + nonceSize + tagSize

func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
func be64(_ v: UInt64) -> [UInt8] { (0..<8).reversed().map { UInt8(v >> (UInt64($0) * 8) & 0xff) } }

func header(epoch: UInt32, eventId: [UInt8], sender: UInt32, timestampMs: UInt64) -> [UInt8] {
    var h: [UInt8] = [version]
    h += be32(epoch)
    h += eventId
    h += be32(sender)
    h += be64(timestampMs)
    precondition(h.count == headerSize)
    return h
}

func seal(key: SymmetricKey, epoch: UInt32, eventId: [UInt8], sender: UInt32,
          timestampMs: UInt64, nonce: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
    let aad = header(epoch: epoch, eventId: eventId, sender: sender, timestampMs: timestampMs)
    let box = try ChaChaPoly.seal(Data(plaintext),
                                  using: key,
                                  nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                                  authenticating: Data(aad))
    return aad + nonce + [UInt8](box.ciphertext) + [UInt8](box.tag)
}

enum OpenError: Error { case tooShort, tooLong, badVersion, authFailed }

func open(key: SymmetricKey, frame: [UInt8]) throws -> [UInt8] {
    guard frame.count >= minFrame else { throw OpenError.tooShort }
    guard frame.count <= headerSize + maxPlaintext + nonceSize + tagSize else { throw OpenError.tooLong }
    guard frame[0] == version else { throw OpenError.badVersion }

    let aad = Array(frame[0..<headerSize])
    let nonce = Array(frame[headerSize..<(headerSize + nonceSize)])
    let ct = Array(frame[(headerSize + nonceSize)..<(frame.count - tagSize)])
    let tag = Array(frame[(frame.count - tagSize)...])

    do {
        let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                                           ciphertext: Data(ct), tag: Data(tag))
        return [UInt8](try ChaChaPoly.open(box, using: key, authenticating: Data(aad)))
    } catch { throw OpenError.authFailed }
}

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> [UInt8] {
    stride(from: 0, to: s.count, by: 2).map { i in
        let a = s.index(s.startIndex, offsetBy: i)
        let b = s.index(a, offsetBy: 2)
        return UInt8(s[a..<b], radix: 16)!
    }
}

// Fixed inputs: vectors must be reproducible, so nothing here is random.
let key = unhex("4f8a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")
let eventId = unhex("0102030405060708090a0b0c0d0e0f10")
let nonce = unhex("a1b2c3d4e5f60718293a4b5c")
let sk = SymmetricKey(data: Data(key))
let epoch: UInt32 = 1
let sender: UInt32 = 0x1000_0001
let ts: UInt64 = 1_757_600_000_000

struct Vector: Encodable {
    let name: String
    let kind: String
    let plaintextUtf8: String?
    let plaintextHex: String?
    let frameHex: String
    let mustReject: Bool
    let note: String?
}

var vectors: [Vector] = []

func positive(_ name: String, _ text: String, epoch: UInt32 = epoch,
              eventId: [UInt8] = eventId, sender: UInt32 = sender,
              ts: UInt64 = ts, nonce: [UInt8] = nonce, note: String? = nil) throws {
    let pt = [UInt8](text.utf8)
    let frame = try seal(key: sk, epoch: epoch, eventId: eventId, sender: sender,
                         timestampMs: ts, nonce: nonce, plaintext: pt)
    let back = try open(key: sk, frame: frame)
    precondition(back == pt, "\(name) failed self round-trip")
    vectors.append(Vector(name: name, kind: "positive", plaintextUtf8: text,
                          plaintextHex: hex(pt), frameHex: hex(frame),
                          mustReject: false, note: note))
}

try positive("basic", "hello baton")
try positive("unicode", "😊すばらしいcafé")
try positive("empty", "")
try positive("totp_leading_zero", "012345")
try positive("multiline", "line1\r\nline2\n")

// max_size uses a repeating pattern rather than random so the vector stays reproducible.
let big = String(repeating: "A", count: maxPlaintext)
try positive("max_size", big)

// Header-field variation (T2/F6). v1.0 used a single header across all vectors,
// so big-endian encoding of epoch, sender and timestamp was never pinned and a
// receiver could get any of them wrong while passing the whole suite.
try positive("epoch_max", "epoch boundary", epoch: 0xffff_ffff,
             note: "uint32 epoch at maximum")
try positive("epoch_zero", "epoch zero", epoch: 0,
             note: "epoch 0 encodes as four zero bytes")
try positive("sender_max", "sender boundary", sender: 0xffff_ffff,
             note: "uint32 sender at maximum")
try positive("sender_zero", "sender zero", sender: 0,
             note: "sender 0 encodes as four zero bytes")
try positive("timestamp_max", "timestamp boundary", ts: 0xffff_ffff_ffff_ffff,
             note: "uint64 timestamp at maximum; pins big-endian 64-bit encoding")
try positive("timestamp_zero", "timestamp zero", ts: 0,
             note: "timestamp 0 encodes as eight zero bytes")
try positive("event_id_all_ff", "event id ff", eventId: [UInt8](repeating: 0xff, count: 16),
             note: "event_id is opaque bytes, not an integer")
try positive("nonce_all_zero", "zero nonce", nonce: [UInt8](repeating: 0, count: 12),
             note: "an all-zero nonce is structurally valid; see SPEC.md on CSPRNG failure, which is how one actually occurs")

let baseFrame = try seal(key: sk, epoch: epoch, eventId: eventId, sender: sender,
                         timestampMs: ts, nonce: nonce, plaintext: [UInt8]("hello baton".utf8))

func negative(_ name: String, _ frame: [UInt8], _ note: String) {
    precondition((try? open(key: sk, frame: frame)) == nil, "\(name) was NOT rejected")
    vectors.append(Vector(name: name, kind: "negative", plaintextUtf8: nil,
                          plaintextHex: nil, frameHex: hex(frame),
                          mustReject: true, note: note))
}

var t1 = baseFrame; t1[5] ^= 0x01
negative("tampered_header", t1, "event_id bit flipped; proves the AAD is bound")

var t2 = baseFrame; t2[headerSize + nonceSize] ^= 0x01
negative("tampered_ciphertext", t2, "first ciphertext byte flipped")

var t3 = baseFrame; t3[t3.count - 1] ^= 0x01
negative("tampered_tag", t3, "last tag byte flipped")

negative("truncated", Array(baseFrame[0..<(minFrame - 1)]), "60 bytes: one below the 61-byte minimum")

// T2/F2: lengths 49-60 passed v1.0's stated minimum of 49 and then produced a
// negative ciphertext length. Swift aborted with SIGTRAP, C# threw. The old
// suite could not catch this: its only short vector was 60 bytes, inside the hole.
negative("len_49_old_min", Array(repeating: 0x01, count: 49),
         "49 bytes: v1.0's incorrect stated minimum; must be rejected")
negative("len_53", Array(repeating: 0x01, count: 53),
         "mid-hole length between the wrong minimum and the real one")
negative("len_60", Array(repeating: 0x01, count: 60),
         "one below the real minimum")
negative("len_0", [], "empty frame")
negative("len_1", [0x01], "single version byte")

var tooLong = baseFrame
tooLong += [UInt8](repeating: 0x00, count: 65_598 - tooLong.count)
negative("oversize", tooLong, "65,598 bytes: one over the maximum frame size")

var t5 = baseFrame; t5[0] = 0x02
negative("bad_version", t5, "version 2 is not this spec")

var t6 = baseFrame; t6[headerSize] ^= 0x01
negative("tampered_nonce", t6, "nonce is outside the AAD but still authenticated via the tag")

struct File: Encodable {
    let spec: String
    let version: Int
    let cipher: String
    let keyHex: String
    let epoch: UInt32
    let senderId: UInt32
    let timestampMs: UInt64
    let eventIdHex: String
    let nonceHex: String
    let vectors: [Vector]
}
let file = File(spec: "batonpass-envelope", version: 1, cipher: "ChaCha20-Poly1305 (RFC 8439)",
                keyHex: hex(key), epoch: epoch, senderId: sender, timestampMs: ts,
                eventIdHex: hex(eventId), nonceHex: hex(nonce), vectors: vectors)

let enc = JSONEncoder()
enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
FileHandle.standardOutput.write(try enc.encode(file))
FileHandle.standardError.write("generated \(vectors.count) vectors\n".data(using: .utf8)!)
