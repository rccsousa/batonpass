using BatonPass.Windows.Agent.Crypto;
using BatonPass.Windows.Agent.State;

namespace BatonPass.Windows.Tests;

public class DedupCacheTests
{
    private static DedupKey Key(byte b) => new(1, 1, new EventId(Enumerable.Repeat(b, 16).ToArray()));

    [Fact]
    public void Add_then_contains_before_expiry()
    {
        var cache = new DedupCache(4096);
        Assert.True(cache.TryAdd(Key(1), expiresAtMs: 1000, nowMs: 0));
        Assert.True(cache.Contains(Key(1), nowMs: 999));
    }

    [Fact]
    public void Expired_entry_is_not_a_duplicate()
    {
        var cache = new DedupCache(4096);
        cache.TryAdd(Key(1), expiresAtMs: 1000, nowMs: 0);
        Assert.False(cache.Contains(Key(1), nowMs: 1000));
        Assert.False(cache.Contains(Key(1), nowMs: 1001));
    }

    [Fact]
    public void Full_cache_rejects_a_new_key()
    {
        var cache = new DedupCache(2);
        Assert.True(cache.TryAdd(Key(1), 1_000_000, 0));
        Assert.True(cache.TryAdd(Key(2), 1_000_000, 0));
        Assert.False(cache.TryAdd(Key(3), 1_000_000, 0));
        Assert.Equal(2, cache.Count);
    }

    [Fact]
    public void Expired_entries_are_purged_to_make_room_but_valid_ones_are_never_evicted()
    {
        var cache = new DedupCache(2);
        cache.TryAdd(Key(1), expiresAtMs: 100, nowMs: 0); // will expire
        cache.TryAdd(Key(2), expiresAtMs: 1_000_000, nowMs: 0); // stays valid

        // Key(1) has expired by now=200; there is room for a new entry.
        Assert.True(cache.TryAdd(Key(3), expiresAtMs: 1_000_000, nowMs: 200));
        Assert.Equal(2, cache.Count);
        Assert.True(cache.Contains(Key(2), 200));
        Assert.True(cache.Contains(Key(3), 200));
    }
}
