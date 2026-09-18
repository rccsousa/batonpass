using BatonPass.Windows.Agent.State;

namespace BatonPass.Windows.Tests;

/// <summary>
/// In-memory doubles for the two persistence seams so the receiver state
/// machine's ordering and fail-closed behaviour can be tested without a real
/// filesystem or DPAPI (which only works on Windows anyway).
/// </summary>
internal sealed class FakeDedupPersistence : IDedupPersistence
{
    public DedupSnapshot? Stored;
    public bool ThrowOnLoad;
    public readonly List<DedupSnapshot> PersistCalls = [];

    /// Records the order persistence calls happen relative to an external
    /// "clipboard write" marker the test appends to this same list's index.
    public readonly List<string> CallOrder = [];

    public DedupSnapshot? Load()
    {
        if (ThrowOnLoad) throw new InvalidDataException("simulated corrupt dedup state");
        return Stored;
    }

    public void Persist(DedupSnapshot snapshot)
    {
        CallOrder.Add("persist");
        PersistCalls.Add(snapshot);
        Stored = snapshot;
    }
}

internal sealed class FakeCounterAnchor : ICounterAnchor
{
    public long? HighWaterMark;
    public bool Tripped;
    public bool ThrowOnRead;

    public long? ReadHighWaterMark()
    {
        if (ThrowOnRead) throw new InvalidDataException("simulated corrupt anchor");
        return HighWaterMark;
    }

    public void WriteHighWaterMark(long value) => HighWaterMark = value;

    public bool ReadTripped()
    {
        if (ThrowOnRead) throw new InvalidDataException("simulated corrupt anchor");
        return Tripped;
    }

    public void WriteTripped(bool tripped) => Tripped = tripped;
}

internal sealed class FakeClock
{
    public long NowMs;
    public long Get() => NowMs;
}
