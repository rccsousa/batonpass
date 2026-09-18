using System.Security.Cryptography;

namespace BatonPass.Windows.Agent.Crypto;

/// <summary>
/// BatonPass envelope wire format v1.1 (../../../crypto/SPEC.md, normative).
/// Ported from the verified reference implementation at
/// ../../../crypto/ref-csharp/Program.cs (Swift/C# byte-exact), split so the
/// receiver state machine (Steps 3/5/6/7, which need caller-held state) sits
/// outside this class and this class only ever implements Steps 1/2/4.
/// </summary>
public static class Envelope
{
    public const byte Version = 0x01;
    public const int HeaderSize = 33;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int MaxPlaintext = 65_536;

    // SPEC.md §3: 61, not v1.0's 49 — the nonce was dropped from that sum, and
    // lengths 49-60 passed the old check and then crashed on negative ciphertext
    // length. Do not "fix" this back down.
    public const int MinFrame = HeaderSize + NonceSize + TagSize;
    public const int MaxFrame = HeaderSize + MaxPlaintext + NonceSize + TagSize;

    public enum RejectReason
    {
        None,
        TooShort,
        TooLong,
        BadVersion,
        WrongEpoch,
        AuthFailed,
    }

    public readonly record struct Header(uint Epoch, EventId EventId, uint SenderId, ulong TimestampMs);

    /// SPEC §4 steps 1-2. Checked before any allocation or decryption, and on
    /// the frame's actual received length — there is no length field, by design.
    public static RejectReason CheckLengthAndVersion(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < MinFrame) return RejectReason.TooShort;
        if (frame.Length > MaxFrame) return RejectReason.TooLong;
        if (frame[0] != Version) return RejectReason.BadVersion;
        return RejectReason.None;
    }

    /// Reads header fields without decrypting. Caller must have already passed
    /// CheckLengthAndVersion. These fields are UNAUTHENTICATED until
    /// TryDecrypt succeeds below — SPEC §4 step 3 reads key_epoch from here only
    /// to route/reject; nothing else may act on this data before step 4.
    public static Header PeekHeader(ReadOnlySpan<byte> frame)
    {
        uint epoch = ReadBe32(frame.Slice(1, 4));
        var eventId = new EventId(frame.Slice(5, 16));
        uint sender = ReadBe32(frame.Slice(21, 4));
        ulong ts = ReadBe64(frame.Slice(25, 8));
        return new Header(epoch, eventId, sender, ts);
    }

    /// SPEC §4 step 4. Nothing above this line may run on unauthenticated input.
    public static bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> frame, out byte[] plaintext)
    {
        var aad = frame[..HeaderSize];
        var nonce = frame.Slice(HeaderSize, NonceSize);
        var ctLen = frame.Length - HeaderSize - NonceSize - TagSize;
        var ct = frame.Slice(HeaderSize + NonceSize, ctLen);
        var tag = frame[^TagSize..];

        var outBuf = new byte[ctLen];
        try
        {
            using var aead = new ChaCha20Poly1305(key);
            aead.Decrypt(nonce, ct, tag, outBuf, aad);
        }
        catch (AuthenticationTagMismatchException)
        {
            plaintext = [];
            return false;
        }

        plaintext = outBuf;
        return true;
    }

    public static byte[] Seal(
        ReadOnlySpan<byte> key,
        uint epoch,
        EventId eventId,
        uint senderId,
        ulong timestampMs,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext)
    {
        // SPEC §3: a sender whose plaintext exceeds this MUST reject and report
        // the item. Never fragment — no receiver has reassembly state.
        if (plaintext.Length > MaxPlaintext)
            throw new ArgumentException("plaintext exceeds max frame payload; caller must reject, not fragment");
        if (nonce.Length != NonceSize)
            throw new ArgumentException("nonce must be 12 bytes");

        Span<byte> header = stackalloc byte[HeaderSize];
        BuildHeader(header, epoch, eventId, senderId, timestampMs);

        var ct = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aead = new ChaCha20Poly1305(key))
        {
            aead.Encrypt(nonce, plaintext, ct, tag, header);
        }

        var frame = new byte[HeaderSize + NonceSize + ct.Length + TagSize];
        header.CopyTo(frame);
        nonce.CopyTo(frame.AsSpan(HeaderSize));
        ct.CopyTo(frame.AsSpan(HeaderSize + NonceSize));
        tag.CopyTo(frame.AsSpan(frame.Length - TagSize));
        return frame;
    }

    /// Sender-side entry point: draws event_id and nonce from the checked CSPRNG
    /// (SecureRandom aborts on a failed/zeroed draw) and seals.
    public static byte[] SealNew(
        ReadOnlySpan<byte> key,
        uint epoch,
        uint senderId,
        ulong timestampMs,
        ReadOnlySpan<byte> plaintext,
        out EventId eventId)
    {
        eventId = new EventId(SecureRandom.GetBytes(16));
        var nonce = SecureRandom.GetBytes(NonceSize);
        return Seal(key, epoch, eventId, senderId, timestampMs, nonce, plaintext);
    }

    private static void BuildHeader(Span<byte> h, uint epoch, EventId eventId, uint sender, ulong ts)
    {
        h[0] = Version;
        WriteBe32(h.Slice(1, 4), epoch);
        eventId.CopyTo(h.Slice(5, 16));
        WriteBe32(h.Slice(21, 4), sender);
        WriteBe64(h.Slice(25, 8), ts);
    }

    private static void WriteBe32(Span<byte> d, uint v)
    {
        d[0] = (byte)(v >> 24);
        d[1] = (byte)(v >> 16);
        d[2] = (byte)(v >> 8);
        d[3] = (byte)v;
    }

    private static void WriteBe64(Span<byte> d, ulong v)
    {
        for (int i = 0; i < 8; i++) d[i] = (byte)(v >> ((7 - i) * 8));
    }

    private static uint ReadBe32(ReadOnlySpan<byte> d) =>
        ((uint)d[0] << 24) | ((uint)d[1] << 16) | ((uint)d[2] << 8) | d[3];

    private static ulong ReadBe64(ReadOnlySpan<byte> d)
    {
        ulong v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | d[i];
        return v;
    }
}
