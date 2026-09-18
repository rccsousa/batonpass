namespace BatonPass.Windows.Agent.Crypto;

/// <summary>
/// 16 opaque bytes (SPEC.md §7: "event_id is opaque bytes, not an integer").
/// Structural equality only — never interpreted numerically.
/// </summary>
public readonly struct EventId : IEquatable<EventId>
{
    private readonly byte[] _bytes;

    public EventId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 16) throw new ArgumentException("event_id must be 16 bytes");
        _bytes = bytes.ToArray();
    }

    public void CopyTo(Span<byte> destination) => _bytes.CopyTo(destination);

    public bool Equals(EventId other) => _bytes.AsSpan().SequenceEqual(other._bytes);

    public override bool Equals(object? obj) => obj is EventId other && Equals(other);

    public override int GetHashCode()
    {
        // 16 bytes from a CSPRNG: fold into a hash without needing every byte
        // to disambiguate in practice, but include all of them for correctness.
        var h = new HashCode();
        foreach (var b in _bytes) h.Add(b);
        return h.ToHashCode();
    }

    public override string ToString() => Convert.ToHexString(_bytes);
}
