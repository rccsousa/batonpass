import CryptoKit
import Foundation

/// Runs crypto/vectors.json against this agent's own Envelope implementation, so
/// the agent is verified against the same fixtures as the reference code rather
/// than against a copy of it.
public enum VectorRunner {
    public struct Vector: Decodable {
        let name: String
        let plaintextHex: String?
        let frameHex: String
        let mustReject: Bool
    }

    public struct File: Decodable {
        let keyHex: String
        let vectors: [Vector]
    }

    public static func run(path: String) -> Bool {
        guard let data = FileManager.default.contents(atPath: path),
              let file = try? JSONDecoder().decode(File.self, from: data) else {
            print("could not read \(path)")
            return false
        }

        let key = SymmetricKey(data: unhex(file.keyHex))
        var pass = 0, fail = 0

        for v in file.vectors {
            let frame = unhex(v.frameHex)
            let result = try? Envelope.open(key: key, frame: frame)

            if v.mustReject {
                if result == nil { pass += 1 } else {
                    print("FAIL \(v.name): accepted a frame that must be rejected"); fail += 1
                }
                continue
            }

            guard let (header, pt) = result else {
                print("FAIL \(v.name): rejected a valid frame"); fail += 1; continue
            }

            guard hex(pt) == (v.plaintextHex ?? "") else {
                print("FAIL \(v.name): plaintext mismatch"); fail += 1; continue
            }

            // Re-seal from the frame's own header, pinning each field's encoding.
            let nonce = frame.subdata(in: Envelope.headerSize..<(Envelope.headerSize + Envelope.nonceSize))
            guard let re = try? Envelope.seal(key: key, header: header, nonce: nonce, plaintext: pt),
                  hex(re) == v.frameHex else {
                print("FAIL \(v.name): re-seal differs"); fail += 1; continue
            }

            pass += 1
        }

        print("\(pass) passed, \(fail) failed")
        return fail == 0
    }

    public static func unhex(_ s: String) -> Data {
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<j], radix: 16) ?? 0)
            i = j
        }
        return out
    }

    public static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
}
