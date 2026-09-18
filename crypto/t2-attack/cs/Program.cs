// T2 adversarial PoCs against crypto/SPEC.md v1.
// Each PoC implements the spec EXACTLY AS WRITTEN and shows what breaks.
// Run: dotnet run -- <poc>   (a1 | a2 | a3 | all)
using System.Security.Cryptography;
using System.Text.Json;

static class T2
{
    const int H = 33, N = 12, T = 16;

    // ---- values taken verbatim from SPEC.md ----
    const int SPEC_MIN_FRAME = 49;      // SPEC.md §3 "min frame | 49 bytes" and §4 step 1
    const int SPEC_MAX_FRAME = 65_597;  // SPEC.md §3

    static byte[] Unhex(string s)
    {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }
    static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    static JsonDocument Vectors() =>
        JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "../../../../../vectors.json")));

    static byte[] Vector(string name)
    {
        using var d = Vectors();
        foreach (var v in d.RootElement.GetProperty("vectors").EnumerateArray())
            if (v.GetProperty("name").GetString() == name)
                return Unhex(v.GetProperty("frameHex").GetString()!);
        throw new Exception("no vector " + name);
    }
    static byte[] Key()
    {
        using var d = Vectors();
        return Unhex(d.RootElement.GetProperty("keyHex").GetString()!);
    }

    // =====================================================================
    // A1 — receiver written strictly to SPEC.md §3/§4.
    // Step 1: "Reject if len(frame) < 49 or len(frame) > 65597."  <-- verbatim
    // Then the spec's own offsets are used to slice, exactly as both
    // reference implementations do.
    // =====================================================================
    static byte[] SpecConformantOpen(byte[] key, byte[] frame)
    {
        if (frame.Length < SPEC_MIN_FRAME) throw new Exception("too_short");   // §4.1
        if (frame.Length > SPEC_MAX_FRAME) throw new Exception("too_long");    // §4.1
        if (frame[0] != 0x01) throw new Exception("bad_version");              // §4.2
        // §4.4 decrypt. Offsets from §2: nonce at 33, ciphertext at 45, tag at 45+Nend.
        var aad   = frame.AsSpan(0, H);
        var nonce = frame.AsSpan(H, N);
        var ct    = frame.AsSpan(H + N, frame.Length - H - N - T);   // <-- negative length
        var tag   = frame.AsSpan(frame.Length - T, T);
        var pt = new byte[ct.Length];
        using var aead = new ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ct, tag, pt, aad);
        return pt;
    }

    static void A1()
    {
        Console.WriteLine("=== A1: SPEC.md's stated min frame (49) is 12 bytes short ===");
        Console.WriteLine($"header {H} + nonce {N} + tag {T} = {H + N + T}  <-- true minimum");
        Console.WriteLine($"SPEC.md §3/§4 say: {SPEC_MIN_FRAME}\n");

        var key = Key();

        // The hostile frame is not even crafted: it is the spec's OWN negative
        // vector, which is 60 bytes and therefore passes the spec's length check.
        var truncated = Vector("truncated");
        Console.WriteLine($"feeding vectors.json 'truncated' ({truncated.Length} bytes) to a spec-conformant receiver...");
        try { SpecConformantOpen(key, truncated); Console.WriteLine("  accepted?!"); }
        catch (Exception e) { Console.WriteLine($"  >>> {e.GetType().Name}: {e.Message}"); }

        // Minimal hostile frame a malicious relay can emit: 49 bytes, version 0x01.
        var evil = new byte[49];
        evil[0] = 0x01;
        Console.WriteLine($"\nfeeding a crafted 49-byte frame (version=0x01, rest zero)...");
        try { SpecConformantOpen(key, evil); Console.WriteLine("  accepted?!"); }
        catch (Exception e) { Console.WriteLine($"  >>> {e.GetType().Name}: {e.Message}"); }

        Console.WriteLine("\nEvery frame length in [49,60] is a remote unhandled exception.");
        Console.WriteLine("The relay needs no key to send one.");
    }

    // =====================================================================
    // A2 — SPEC.md §4 step 5: "Reject if |now - timestamp_ms| > 60_000".
    // timestamp_ms is a uint64 (§2). Implemented over the field's own type,
    // as an implementer reading §2 + §4 would.
    // =====================================================================
    static bool Step5_AsSpecced(ulong nowMs, ulong tsMs)
    {
        // "|now - timestamp_ms|" in unsigned 64-bit arithmetic.
        ulong d = nowMs - tsMs;              // wraps when the sender's clock is ahead
        return d <= 60_000;
    }
    static bool Step5_Correct(long nowMs, long tsMs) => Math.Abs(nowMs - tsMs) <= 60_000;

    static void A2()
    {
        Console.WriteLine("=== A2: §4 step 5 over a uint64 field ===");
        ulong now = 1_757_600_000_000UL;
        foreach (var skew in new long[] { 0, -1, -1000, -30_000, -59_000, 1000, 61_000 })
        {
            ulong ts = (ulong)((long)now + (-skew)); // skew<0 => sender clock AHEAD
            bool specced = Step5_AsSpecced(now, ts);
            bool correct = Step5_Correct((long)now, (long)ts);
            string lbl = skew < 0 ? $"sender {(-skew)}ms AHEAD" : $"sender {skew}ms behind";
            Console.WriteLine($"  {lbl,-28} spec-as-written: {(specced ? "accept" : "REJECT")}   intended: {(correct ? "accept" : "reject")}   {(specced != correct ? "<-- MISMATCH" : "")}");
        }
        Console.WriteLine("\nA Windows receiver built this way rejects EVERY frame from a device");
        Console.WriteLine("whose clock is even 1 ms ahead. That is Milestone 1 failing closed,");
        Console.WriteLine("silently, on normal clock skew. (Swift traps instead -- see swift/ PoC.)");
    }

    // =====================================================================
    // A3 — SPEC.md §7: "tampered_header ... is the only thing proving the AAD
    // is genuinely bound, and a broken AAD implementation passes every other
    // vector in the file."  Test that claim.
    // =====================================================================
    static bool OpenWithAad(byte[] key, byte[] frame, ReadOnlySpan<byte> aad)
    {
        var nonce = frame.AsSpan(H, N);
        var ct = frame.AsSpan(H + N, frame.Length - H - N - T);
        var tag = frame.AsSpan(frame.Length - T, T);
        var pt = new byte[ct.Length];
        try { using var a = new ChaCha20Poly1305(key); a.Decrypt(nonce, ct, tag, pt, aad); return true; }
        catch (AuthenticationTagMismatchException) { return false; }
    }

    static void A3()
    {
        Console.WriteLine("=== A3: is tampered_header really the only evidence of AAD binding? ===");
        var key = Key();
        var basic = Vector("basic");

        var broken = new (string name, byte[] aad)[]
        {
            ("AAD omitted entirely",        Array.Empty<byte>()),
            ("AAD = version byte only",     basic[..1]),
            ("AAD = header minus version",  basic[1..H]),
            ("AAD = header + nonce (45B)",  basic[..(H + N)]),
            ("AAD = whole frame",           basic),
        };
        foreach (var (name, aad) in broken)
        {
            bool ok = OpenWithAad(key, basic, aad);
            Console.WriteLine($"  positive vector 'basic' with {name,-28} -> {(ok ? "ACCEPTED" : "rejected")}");
        }
        Console.WriteLine("\nEvery broken-AAD variant already fails the POSITIVE vectors.");
        Console.WriteLine("The §7 claim is false: tampered_header proves nothing the positive");
        Console.WriteLine("vectors + the C# re-seal check did not already prove.");
        Console.WriteLine("\nWhat the suite really does NOT cover: all 12 vectors share ONE header");
        Console.WriteLine("(epoch=1, sender=0x10000001, ts=1757600000000, same event_id, same nonce).");
        using var d = Vectors();
        var set = new HashSet<string>();
        foreach (var v in d.RootElement.GetProperty("vectors").EnumerateArray())
            set.Add(Hex(Unhex(v.GetProperty("frameHex").GetString()!).AsSpan(1, H - 1)));
        Console.WriteLine($"  distinct header bodies across all vectors (excl. version byte): {set.Count}");
        Console.WriteLine("  => no vector varies epoch, sender_id or timestamp at all.");
    }

    static int Main(string[] a)
    {
        var which = a.Length > 0 ? a[0] : "all";
        if (which is "a1" or "all") { A1(); Console.WriteLine(); }
        if (which is "a2" or "all") { A2(); Console.WriteLine(); }
        if (which is "a3" or "all") { A3(); Console.WriteLine(); }
        if (which is "a4" or "all") { Fuzz.Run(Key(), Vector("basic")); Console.WriteLine(); }
        return 0;
    }
}
