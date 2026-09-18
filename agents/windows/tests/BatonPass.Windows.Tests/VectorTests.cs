using System.Text.Json;
using BatonPass.Windows.Agent.Crypto;

namespace BatonPass.Windows.Tests;

/// <summary>
/// Runs all 26 conformance vectors from crypto/vectors.json against this
/// project's Envelope implementation. Mirrors crypto/ref-csharp/Program.cs's
/// scope exactly: only SPEC.md §4 steps 1/2/4 (length, version, decrypt+tag) —
/// the vectors do not and cannot exercise epoch/freshness/dedup (SPEC.md §7,
/// "What the vectors do NOT cover"). Those are covered separately in
/// ReceiverStateMachineTests.
/// </summary>
public class VectorTests
{
    private sealed class VectorFile
    {
        public string KeyHex { get; set; } = "";
        public List<VectorCase> Vectors { get; set; } = [];
    }

    private sealed class VectorCase
    {
        public string Name { get; set; } = "";
        public string FrameHex { get; set; } = "";
        public bool MustReject { get; set; }
        public string? PlaintextHex { get; set; }
    }

    private static readonly VectorFile Vectors = LoadVectors();

    private static VectorFile LoadVectors()
    {
        string path = TestPaths.RepoFile("crypto/vectors.json");
        string json = File.ReadAllText(path);
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        return JsonSerializer.Deserialize<VectorFile>(json, opts)!;
    }

    public static IEnumerable<object[]> Cases() => Vectors.Vectors.Select(v => new object[] { v.Name });

    private static VectorCase Find(string name) => Vectors.Vectors.Single(v => v.Name == name);

    [Fact]
    public void Loaded_all_26_vectors()
    {
        Assert.Equal(26, Vectors.Vectors.Count);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Vector(string name)
    {
        var v = Find(name);
        byte[] key = Convert.FromHexString(Vectors.KeyHex);
        byte[] frame = Convert.FromHexString(v.FrameHex);

        bool opened = TryOpen(key, frame, out var plaintext, out var reason);

        if (v.MustReject)
        {
            Assert.False(opened, $"{name}: accepted a frame that must be rejected");
            return;
        }

        Assert.True(opened, $"{name}: rejected a valid frame ({reason})");
        Assert.Equal(v.PlaintextHex, Convert.ToHexString(plaintext).ToLowerInvariant());

        // Re-seal from the header fields parsed out of the frame itself (not
        // file-level defaults) — vectors vary epoch/sender/timestamp/event_id
        // per-frame, and reading those back pins each field's BE encoding,
        // exactly as ref-csharp's re-seal check does.
        var header = Envelope.PeekHeader(frame);
        var nonce = frame.AsSpan(Envelope.HeaderSize, Envelope.NonceSize);
        byte[] resealed = Envelope.Seal(key, header.Epoch, header.EventId, header.SenderId, header.TimestampMs, nonce, plaintext);
        Assert.Equal(v.FrameHex, Convert.ToHexString(resealed).ToLowerInvariant());
    }

    private static bool TryOpen(byte[] key, byte[] frame, out byte[] plaintext, out string reason)
    {
        var lengthVersion = Envelope.CheckLengthAndVersion(frame);
        if (lengthVersion != Envelope.RejectReason.None)
        {
            plaintext = [];
            reason = lengthVersion.ToString();
            return false;
        }

        if (!Envelope.TryDecrypt(key, frame, out plaintext))
        {
            reason = "auth_failed";
            return false;
        }

        reason = "ok";
        return true;
    }
}
