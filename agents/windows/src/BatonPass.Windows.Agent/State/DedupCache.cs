namespace BatonPass.Windows.Agent.State;

/// <summary>
/// Pure in-memory replay cache, SPEC.md §5. No I/O — persistence is a separate
/// concern (<see cref="IDedupPersistence"/>) so the ordering invariant in §4
/// step 7 ("persist the dedup entry, then write the clipboard") is enforced by
/// the caller sequencing, not by this class.
/// </summary>
public sealed class DedupCache
{
    private readonly Dictionary<DedupKey, long> _entries;
    private readonly int _capacity;

    public DedupCache(int capacity, IEnumerable<KeyValuePair<DedupKey, long>>? seed = null)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _entries = seed is null
            ? new Dictionary<DedupKey, long>()
            : new Dictionary<DedupKey, long>(seed);
    }

    public int Count => _entries.Count;

    public IReadOnlyDictionary<DedupKey, long> Entries => _entries;

    public bool Contains(DedupKey key, long nowMs)
    {
        // An expired entry is not a duplicate. It also gets swept below on the
        // next TryAdd, but a bare lookup must not treat it as still valid.
        return _entries.TryGetValue(key, out var expiresAt) && expiresAt > nowMs;
    }

    /// <summary>
    /// Adds <paramref name="key"/> with retention until <paramref name="expiresAtMs"/>.
    /// Purges expired entries first to reclaim space, then, if still full, rejects
    /// rather than evicting a still-valid entry (SPEC.md §5: "when the cache is
    /// full, reject new traffic. Never evict a still-valid entry").
    /// </summary>
    public bool TryAdd(DedupKey key, long expiresAtMs, long nowMs)
    {
        if (_entries.ContainsKey(key))
        {
            // Already present and (by construction, callers check Contains first)
            // still valid — this path exists for direct unit testing only.
            return true;
        }

        PurgeExpired(nowMs);

        if (_entries.Count >= _capacity)
            return false;

        _entries[key] = expiresAtMs;
        return true;
    }

    private void PurgeExpired(long nowMs)
    {
        if (_entries.Count == 0) return;
        List<DedupKey>? toRemove = null;
        foreach (var (k, expiresAt) in _entries)
        {
            if (expiresAt <= nowMs)
            {
                (toRemove ??= []).Add(k);
            }
        }
        if (toRemove is null) return;
        foreach (var k in toRemove) _entries.Remove(k);
    }
}
