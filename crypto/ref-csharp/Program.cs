using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

static class Verifier
{

// Independent verifier for the BatonPass v1 envelope. Reads ../vectors.json,
// which was produced by ref-swift, and checks that a second language agrees.
// See ../SPEC.md — normative.

    const byte Version = 0x01;
    const int HeaderSize = 33;
    const int NonceSize = 12;
    const int TagSize = 16;
    const int MaxPlaintext = 65_536;
    const int MinFrame = HeaderSize + NonceSize + TagSize; // 61 — SPEC.md §3

    static byte[] Unhex(string s)
{
    var b = new byte[s.Length / 2];
    for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
    return b;
}
    static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    static void WriteBe32(Span<byte> d, uint v)
{
    d[0] = (byte)(v >> 24); d[1] = (byte)(v >> 16); d[2] = (byte)(v >> 8); d[3] = (byte)v;
}
    static void WriteBe64(Span<byte> d, ulong v)
{
    for (int i = 0; i < 8; i++) d[i] = (byte)(v >> ((7 - i) * 8));
}

    static uint ReadBe32(ReadOnlySpan<byte> d) =>
        ((uint)d[0] << 24) | ((uint)d[1] << 16) | ((uint)d[2] << 8) | d[3];

    static ulong ReadBe64(ReadOnlySpan<byte> d)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | d[i];
        return v;
    }

    static byte[] BuildHeader(uint epoch, byte[] eventId, uint sender, ulong ts)
{
    var h = new byte[HeaderSize];
    h[0] = Version;
    WriteBe32(h.AsSpan(1, 4), epoch);
    eventId.CopyTo(h.AsSpan(5, 16));
    WriteBe32(h.AsSpan(21, 4), sender);
    WriteBe64(h.AsSpan(25, 8), ts);
    return h;
}

    static byte[] Seal(byte[] key, uint epoch, byte[] eventId, uint sender, ulong ts,
                   byte[] nonce, byte[] plaintext)
{
    var aad = BuildHeader(epoch, eventId, sender, ts);
    var ct = new byte[plaintext.Length];
    var tag = new byte[TagSize];
    using var aead = new ChaCha20Poly1305(key);
    aead.Encrypt(nonce, plaintext, ct, tag, aad);

    var frame = new byte[HeaderSize + NonceSize + ct.Length + TagSize];
    aad.CopyTo(frame.AsSpan(0));
    nonce.CopyTo(frame.AsSpan(HeaderSize));
    ct.CopyTo(frame.AsSpan(HeaderSize + NonceSize));
    tag.CopyTo(frame.AsSpan(frame.Length - TagSize));
    return frame;
}

    static bool TryOpen(byte[] key, byte[] frame, out byte[] plaintext, out string reason)
{
    plaintext = Array.Empty<byte>();

    // Length and version are checked before any allocation or decryption.
    if (frame.Length < MinFrame) { reason = "too_short"; return false; }
    if (frame.Length > HeaderSize + MaxPlaintext + NonceSize + TagSize) { reason = "too_long"; return false; }
    if (frame[0] != Version) { reason = "bad_version"; return false; }

    var aad = frame.AsSpan(0, HeaderSize);
    var nonce = frame.AsSpan(HeaderSize, NonceSize);
    var ct = frame.AsSpan(HeaderSize + NonceSize, frame.Length - HeaderSize - NonceSize - TagSize);
    var tag = frame.AsSpan(frame.Length - TagSize, TagSize);

    var outBuf = new byte[ct.Length];
    try
    {
        using var aead = new ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ct, tag, outBuf, aad);
    }
    catch (AuthenticationTagMismatchException) { reason = "auth_failed"; return false; }

    plaintext = outBuf;
    reason = "ok";
    return true;
}

    static int Main(string[] args)
    {
        var path = args.Length > 0 ? args[0] : "../vectors.json";

using var doc = JsonDocument.Parse(File.ReadAllText(path));
var root = doc.RootElement;

var key = Unhex(root.GetProperty("keyHex").GetString()!);
var epoch = root.GetProperty("epoch").GetUInt32();
var sender = root.GetProperty("senderId").GetUInt32();
var ts = root.GetProperty("timestampMs").GetUInt64();
var eventId = Unhex(root.GetProperty("eventIdHex").GetString()!);
var nonce = Unhex(root.GetProperty("nonceHex").GetString()!);

int pass = 0, fail = 0;
foreach (var v in root.GetProperty("vectors").EnumerateArray())
{
    var name = v.GetProperty("name").GetString()!;
    var frame = Unhex(v.GetProperty("frameHex").GetString()!);
    var mustReject = v.GetProperty("mustReject").GetBoolean();

    var opened = TryOpen(key, frame, out var pt, out var reason);

    if (mustReject)
    {
        if (opened) { Console.WriteLine($"FAIL {name}: accepted a frame that must be rejected"); fail++; }
        else { Console.WriteLine($"pass {name}: rejected ({reason})"); pass++; }
        continue;
    }

    if (!opened) { Console.WriteLine($"FAIL {name}: rejected a valid frame ({reason})"); fail++; continue; }

    var expectHex = v.GetProperty("plaintextHex").GetString()!;
    if (Hex(pt) != expectHex) { Console.WriteLine($"FAIL {name}: plaintext mismatch"); fail++; continue; }

    // Re-seal from the header fields parsed out of the frame itself, not from the
    // file-level defaults: vectors vary epoch, sender, timestamp, event_id and
    // nonce, and reading those back is what pins each field's big-endian encoding.
    var vEpoch = ReadBe32(frame.AsSpan(1, 4));
    var vEventId = frame.AsSpan(5, 16).ToArray();
    var vSender = ReadBe32(frame.AsSpan(21, 4));
    var vTs = ReadBe64(frame.AsSpan(25, 8));
    var vNonce = frame.AsSpan(HeaderSize, NonceSize).ToArray();
    var reSealed = Seal(key, vEpoch, vEventId, vSender, vTs, vNonce, pt);
    if (Hex(reSealed) != v.GetProperty("frameHex").GetString()!)
    {
        Console.WriteLine($"FAIL {name}: re-seal produced different bytes than Swift");
        fail++; continue;
    }

    Console.WriteLine($"pass {name}: {pt.Length}B plaintext, frame reproduced byte-exactly");
    pass++;
}

Console.WriteLine($"\n{pass} passed, {fail} failed");
        return fail == 0 ? 0 : 1;
    }
}
