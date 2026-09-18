namespace BatonPass.Windows.Agent.State;

public sealed record DedupSnapshot(
    IReadOnlyDictionary<DedupKey, long> Entries,
    long AcceptanceCounter,
    long LastObservedNowMs);

/// <summary>
/// Durable storage for the dedup cache and acceptance counter. SPEC.md §6:
/// non-backed-up, device-local (DPAPI machine scope on Windows).
/// </summary>
public interface IDedupPersistence
{
    /// Returns null if no state exists yet (first run). Throws on any state that
    /// exists but cannot be trusted (decrypt failure, parse failure, schema
    /// mismatch) — callers must treat a thrown exception as SPEC.md §5's
    /// "missing or corrupt cache state" and fail closed, never default to empty.
    DedupSnapshot? Load();

    /// Must complete (durably) before the caller writes the clipboard.
    void Persist(DedupSnapshot snapshot);
}

/// <summary>
/// Independent monotonic high-water mark for the acceptance counter, stored
/// separately from <see cref="IDedupPersistence"/> so a restore that rolls back
/// only the dedup state file (SPEC.md §6, "backup and restore") is still
/// detectable — the anchor does not travel with that file.
/// </summary>
public interface ICounterAnchor
{
    /// Null means never written (first run).
    long? ReadHighWaterMark();
    void WriteHighWaterMark(long value);

    /// Null means never written (first run, not tripped).
    bool ReadTripped();
    void WriteTripped(bool tripped);
}
