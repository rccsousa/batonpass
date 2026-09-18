// A4 -- fuzz the reference receiver AS SHIPPED (ref-csharp/Program.cs TryOpen,
// copied verbatim) to establish what is NOT broken.
using System.Security.Cryptography;

static class Fuzz
{
    const byte Version = 0x01;
    const int HeaderSize = 33, NonceSize = 12, TagSize = 16, MaxPlaintext = 65_536;
    const int MinFrame = HeaderSize + NonceSize + TagSize;   // 61, NOT the spec's 49

    // verbatim from crypto/ref-csharp/Program.cs
    static bool TryOpen(byte[] key, byte[] frame, out byte[] plaintext, out string reason)
    {
        plaintext = Array.Empty<byte>();
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
        plaintext = outBuf; reason = "ok"; return true;
    }

    public static void Run(byte[] key, byte[] baseFrame)
    {
        Console.WriteLine("=== A4: fuzzing ref-csharp TryOpen as shipped ===");
        var rng = new Random(1337);
        long n = 0, crashes = 0, accepted = 0, acceptedNotBase = 0;
        var lengths = new List<int>();
        for (int L = 0; L <= 80; L++) lengths.Add(L);
        foreach (var L in new[] { 1000, 65_596, 65_597, 65_598, 100_000 }) lengths.Add(L);

        // exhaustive-ish over boundary lengths, random content
        foreach (var L in lengths)
            for (int rep = 0; rep < 200; rep++)
            {
                var f = new byte[L];
                rng.NextBytes(f);
                if (rep % 2 == 0 && L > 0) f[0] = 0x01;
                n++;
                try { if (TryOpen(key, f, out _, out _)) { accepted++; acceptedNotBase++; } }
                catch (Exception e) { crashes++; Console.WriteLine($"  CRASH len={L}: {e.GetType().Name}"); }
            }

        // mutations of a genuine frame: every single-byte position, random value
        for (int i = 0; i < baseFrame.Length; i++)
            for (int rep = 0; rep < 8; rep++)
            {
                var f = (byte[])baseFrame.Clone();
                f[i] = (byte)rng.Next(256);
                n++;
                try { if (TryOpen(key, f, out _, out _)) { accepted++; if (!f.AsSpan().SequenceEqual(baseFrame)) acceptedNotBase++; } }
                catch (Exception e) { crashes++; Console.WriteLine($"  CRASH mutate[{i}]: {e.GetType().Name}"); }
            }

        // truncations and extensions of a genuine frame
        for (int L = 0; L <= baseFrame.Length + 40; L++)
        {
            var f = new byte[L];
            Array.Copy(baseFrame, f, Math.Min(L, baseFrame.Length));
            n++;
            try { if (TryOpen(key, f, out _, out _)) { accepted++; if (!f.AsSpan().SequenceEqual(baseFrame)) acceptedNotBase++; } }
            catch (Exception e) { crashes++; Console.WriteLine($"  CRASH trunc len={L}: {e.GetType().Name}"); }
        }

        Console.WriteLine($"  {n} frames, {crashes} unhandled exceptions, {accepted} accepted");
        Console.WriteLine($"  accepted frames that differ from the genuine frame: {acceptedNotBase}");
        Console.WriteLine(acceptedNotBase == 0
            ? "  (all acceptances were no-op mutations reproducing the genuine frame -- correct)"
            : "  !! FORGERY");
        Console.WriteLine("  => the SHIPPED reference is length-safe. The 49 vs 61 bug is a");
        Console.WriteLine("     SPEC-vs-code divergence: it lands in whatever T4/T5/T6 write from SPEC.md.");
    }
}
