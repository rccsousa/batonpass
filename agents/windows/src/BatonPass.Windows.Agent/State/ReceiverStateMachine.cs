using BatonPass.Windows.Agent.Crypto;

namespace BatonPass.Windows.Agent.State;

public enum AcceptStatus
{
    Accepted,
    RejectedTooShort,
    RejectedTooLong,
    RejectedBadVersion,
    RejectedWrongEpoch,
    RejectedAuthFailed,
    RejectedStale,
    RejectedDuplicate,
    RejectedCacheFull,
    RejectedTripped,
}

public readonly record struct AcceptOutcome(AcceptStatus Status, byte[]? Plaintext)
{
    public bool IsAccepted => Status == AcceptStatus.Accepted;
}

/// <summary>
/// SPEC.md §4 receiver algorithm, in order, plus §5 replay defence and §6's
/// monotonic-counter anti-rollback requirement. Order is normative — do not
/// reorder for efficiency (SPEC.md §4 preamble).
/// </summary>
public sealed class ReceiverStateMachine
{
    private const long FreshnessWindowMs = 60_000;
    private const long RetentionExtraMs = 60_000;

    private readonly byte[] _key;
    private readonly uint _currentEpoch;
    private readonly Func<long> _nowMs;
    private readonly IDedupPersistence _persistence;
    private readonly ICounterAnchor _anchor;

    private DedupCache _cache;
    private long _acceptanceCounter;
    private long _lastObservedNowMs;
    private bool _tripped;

    public ReceiverStateMachine(
        byte[] key,
        uint currentEpoch,
        int cacheCapacity,
        IDedupPersistence persistence,
        ICounterAnchor anchor,
        Func<long> nowMs)
    {
        if (cacheCapacity < 4096)
            throw new ArgumentOutOfRangeException(nameof(cacheCapacity), "SPEC.md §5: capacity must be at least 4096");

        _key = key;
        _currentEpoch = currentEpoch;
        _persistence = persistence;
        _anchor = anchor;
        _nowMs = nowMs;
        _cache = new DedupCache(cacheCapacity);

        LoadAtStartup(cacheCapacity);
    }

    public bool IsTripped => _tripped;

    public long AcceptanceCounter => _acceptanceCounter;

    private void LoadAtStartup(int cacheCapacity)
    {
        try
        {
            LoadAtStartupUnguarded(cacheCapacity);
        }
        catch
        {
            // Any failure reading either store — corrupt DPAPI blob, unparseable
            // JSON, missing directory permissions — is "corrupt or missing cache
            // state" (§5). Fail closed rather than let an unhandled exception
            // decide whether the receiver starts.
            Trip();
        }
    }

    private void LoadAtStartupUnguarded(int cacheCapacity)
    {
        // §5: "must not clear itself on a timer" — the trip flag lives in the
        // anchor, independent of whether the dedup file currently looks valid,
        // so a regenerated-but-empty file cannot silently un-trip the receiver.
        if (_anchor.ReadTripped())
        {
            _tripped = true;
            return;
        }

        DedupSnapshot? snapshot = _persistence.Load();
        var anchorHwm = _anchor.ReadHighWaterMark();

        if (snapshot is null)
        {
            _acceptanceCounter = 0;
            _lastObservedNowMs = 0;
            if (anchorHwm is > 0)
            {
                // The dedup file is gone but the anchor remembers a nonzero
                // counter: exactly the "restored an old backup" shape. Fail closed.
                Trip();
            }
            else
            {
                _anchor.WriteHighWaterMark(0);
            }
            return;
        }

        // §6/T2-F5: the acceptance counter must never move backwards. Compared
        // against a store that does not travel with the dedup file, so a restore
        // of just the file (or just the anchor) is still caught.
        if (anchorHwm is long hwm && snapshot.AcceptanceCounter != hwm)
        {
            Trip();
            return;
        }

        long now = _nowMs();
        if (snapshot.LastObservedNowMs > now)
        {
            // Wall clock is behind where this receiver has already been:
            // detected clock rollback (§5). Fail closed.
            Trip();
            return;
        }

        _cache = new DedupCache(cacheCapacity, snapshot.Entries);
        _acceptanceCounter = snapshot.AcceptanceCounter;
        _lastObservedNowMs = snapshot.LastObservedNowMs;
        if (anchorHwm is null) _anchor.WriteHighWaterMark(_acceptanceCounter);
    }

    private void Trip()
    {
        _tripped = true;
        try
        {
            // Best-effort: the in-memory trip already blocks TryAccept for the
            // life of this process even if the anchor itself is unwritable.
            _anchor.WriteTripped(true);
        }
        catch
        {
            // Swallowed deliberately — see comment above. Never let a failed
            // "record that we failed closed" throw turn into an unhandled crash.
        }
    }

    /// <summary>
    /// Explicit operator action per SPEC.md §5 ("resume after clock correction").
    /// Clears the tripped state and flushes the dedup cache — entries dated
    /// under a bad clock cannot be trusted. Never called automatically.
    /// </summary>
    public void ResumeAfterClockCorrection(int cacheCapacity)
    {
        long resumeCounter = Math.Max(_acceptanceCounter, _anchor.ReadHighWaterMark() ?? 0);
        _cache = new DedupCache(cacheCapacity);
        _acceptanceCounter = resumeCounter;
        _lastObservedNowMs = _nowMs();
        _tripped = false;
        _anchor.WriteTripped(false);
        _anchor.WriteHighWaterMark(_acceptanceCounter);
        _persistence.Persist(new DedupSnapshot(_cache.Entries, _acceptanceCounter, _lastObservedNowMs));
    }

    public AcceptOutcome TryAccept(ReadOnlySpan<byte> frame)
    {
        if (_tripped) return new AcceptOutcome(AcceptStatus.RejectedTripped, null);

        long now = _nowMs();
        if (now < _lastObservedNowMs)
        {
            // Live clock rollback observed mid-run.
            Trip();
            return new AcceptOutcome(AcceptStatus.RejectedTripped, null);
        }
        _lastObservedNowMs = Math.Max(_lastObservedNowMs, now);

        // Step 1-2.
        var reason = Envelope.CheckLengthAndVersion(frame);
        switch (reason)
        {
            case Envelope.RejectReason.TooShort: return new AcceptOutcome(AcceptStatus.RejectedTooShort, null);
            case Envelope.RejectReason.TooLong: return new AcceptOutcome(AcceptStatus.RejectedTooLong, null);
            case Envelope.RejectReason.BadVersion: return new AcceptOutcome(AcceptStatus.RejectedBadVersion, null);
        }

        // Step 3. Epoch is read from the unauthenticated header on purpose
        // (§4): a forged epoch just routes to a rejection, nothing else acts on
        // header fields before step 4.
        var header = Envelope.PeekHeader(frame);
        if (header.Epoch != _currentEpoch)
            return new AcceptOutcome(AcceptStatus.RejectedWrongEpoch, null);

        // Step 4. Nothing above this line ran on authenticated input; nothing
        // below runs on anything else.
        if (!Envelope.TryDecrypt(_key, frame, out var plaintext))
            return new AcceptOutcome(AcceptStatus.RejectedAuthFailed, null);

        // Step 5, freshness window. Reject a hostile-ahead timestamp with a pure
        // unsigned comparison before any arithmetic can touch it (SPEC.md §4);
        // only once it is proven <= now + window is a checked signed cast safe.
        ulong nowU = (ulong)now;
        ulong upperBoundU = nowU + FreshnessWindowMs;
        if (header.TimestampMs > upperBoundU)
            return new AcceptOutcome(AcceptStatus.RejectedStale, null);

        long ts = checked((long)header.TimestampMs);
        if (ts < now - FreshnessWindowMs)
            return new AcceptOutcome(AcceptStatus.RejectedStale, null);

        // Step 6, dedup.
        var key = new DedupKey(header.Epoch, header.SenderId, header.EventId);
        if (_cache.Contains(key, now))
            return new AcceptOutcome(AcceptStatus.RejectedDuplicate, null);

        // §5 retention: max(now_at_acceptance, timestamp_ms) + 60s.
        long expiresAt = Math.Max(now, ts) + RetentionExtraMs;
        if (!_cache.TryAdd(key, expiresAt, now))
            return new AcceptOutcome(AcceptStatus.RejectedCacheFull, null);

        // Step 7: persist the dedup entry, THEN — and only in the caller, after
        // this method returns Accepted — write the clipboard.
        _acceptanceCounter++;
        _anchor.WriteHighWaterMark(_acceptanceCounter);
        _persistence.Persist(new DedupSnapshot(_cache.Entries, _acceptanceCounter, _lastObservedNowMs));

        return new AcceptOutcome(AcceptStatus.Accepted, plaintext);
    }
}
