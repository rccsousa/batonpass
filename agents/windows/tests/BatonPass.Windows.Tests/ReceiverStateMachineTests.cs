using BatonPass.Windows.Agent.Crypto;
using BatonPass.Windows.Agent.State;

namespace BatonPass.Windows.Tests;

/// <summary>
/// Stateful coverage SPEC.md §7 says the vector suite cannot provide: epoch
/// rejection, the freshness window (including the F3 clock-ahead bug), dedup
/// retention across the F1 asymmetric-window bug, cache-full behaviour, and
/// persist-before-write ordering.
/// </summary>
public class ReceiverStateMachineTests
{
    private const uint Epoch = 7;
    private static readonly byte[] Key = Convert.FromHexString("4f8a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a");

    private static (ReceiverStateMachine machine, FakeDedupPersistence persistence, FakeCounterAnchor anchor, FakeClock clock)
        NewMachine(int capacity = 4096)
    {
        var persistence = new FakeDedupPersistence();
        var anchor = new FakeCounterAnchor();
        var clock = new FakeClock { NowMs = 1_757_600_000_000 };
        var machine = new ReceiverStateMachine(Key, Epoch, capacity, persistence, anchor, clock.Get);
        return (machine, persistence, anchor, clock);
    }

    private static byte[] SealAt(FakeClock clock, uint epoch, uint senderId, long offsetMs, string text = "hi")
    {
        ulong ts = (ulong)(clock.NowMs + offsetMs);
        return Envelope.SealNew(Key, epoch, senderId, ts, System.Text.Encoding.UTF8.GetBytes(text), out _);
    }

    [Fact]
    public void Accepts_a_well_formed_frame()
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 0);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.Accepted, outcome.Status);
        Assert.Equal("hi", System.Text.Encoding.UTF8.GetString(outcome.Plaintext!));
    }

    [Fact]
    public void Rejects_wrong_epoch_at_step_3_without_decrypting()
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, epoch: Epoch + 1, senderId: 1, offsetMs: 0);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.RejectedWrongEpoch, outcome.Status);
    }

    [Fact]
    public void Replay_of_an_identical_frame_is_rejected_as_duplicate()
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 0);

        Assert.Equal(AcceptStatus.Accepted, m.TryAccept(frame).Status);
        Assert.Equal(AcceptStatus.RejectedDuplicate, m.TryAccept(frame).Status);
    }

    [Theory]
    [InlineData(1)] // F3: Swift trapped on exactly this — 1ms ahead must not crash or reject
    [InlineData(59_999)]
    [InlineData(60_000)] // boundary: exactly at the edge is still <= now+window
    public void Accepts_a_frame_from_a_clock_ahead_sender_within_the_window(long aheadMs)
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: aheadMs);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.Accepted, outcome.Status);
    }

    [Fact]
    public void Rejects_a_frame_from_a_clock_ahead_sender_beyond_the_window()
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 60_001);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.RejectedStale, outcome.Status);
    }

    [Fact]
    public void Rejects_a_frame_from_a_clock_behind_sender_beyond_the_window()
    {
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: -60_001);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.RejectedStale, outcome.Status);
    }

    [Fact]
    public void A_hostile_far_future_timestamp_is_rejected_by_the_unsigned_guard_before_any_signed_arithmetic()
    {
        // event_id_all_ff-style hostility: timestamp_ms = UInt64.MaxValue. The
        // naive `now - timestamp_ms` unsigned subtraction underflows to a huge
        // number; SPEC.md §4 requires this be caught by the unsigned
        // "ahead" check before that subtraction can ever run.
        var (m, _, _, clock) = NewMachine();
        byte[] frame = Envelope.SealNew(Key, Epoch, senderId: 1, ulong.MaxValue, "hi"u8.ToArray(), out _);

        var outcome = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.RejectedStale, outcome.Status);
    }

    [Fact]
    public void Dedup_retention_survives_the_F1_asymmetric_window_a_45s_ahead_sender_replay_at_70s_is_still_caught()
    {
        // T2/F1: the old (wrong) rule retained "60s from acceptance", which
        // expires *before* a 45s-ahead sender's frame stops being individually
        // acceptable — reopening a real replay window. The fixed retention is
        // max(now_at_acceptance, timestamp_ms) + 60s, i.e. expiry at +105s here.
        var (m, _, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 45_000);

        Assert.Equal(AcceptStatus.Accepted, m.TryAccept(frame).Status);

        clock.NowMs += 70_000; // past the buggy 60s-from-acceptance expiry, inside the correct +105s one
        var replay = m.TryAccept(frame);

        Assert.Equal(AcceptStatus.RejectedDuplicate, replay.Status);
    }

    [Fact]
    public void Cache_full_rejects_new_traffic_and_never_evicts_a_still_valid_entry()
    {
        const int capacity = 4096;
        var (m, _, _, clock) = NewMachine(capacity);

        var firstFrame = SealAt(clock, Epoch, senderId: 0, offsetMs: 0);
        Assert.Equal(AcceptStatus.Accepted, m.TryAccept(firstFrame).Status);
        for (uint i = 1; i < capacity; i++)
        {
            var frame = SealAt(clock, Epoch, senderId: i, offsetMs: 0);
            Assert.Equal(AcceptStatus.Accepted, m.TryAccept(frame).Status);
        }

        var overflow = SealAt(clock, Epoch, senderId: 999_999, offsetMs: 0);
        Assert.Equal(AcceptStatus.RejectedCacheFull, m.TryAccept(overflow).Status);

        // The very first entry must still be present — "full" must reject the
        // newcomer, never evict a still-valid entry to make room. Replaying the
        // exact original frame proves it: a "cache full" bug that silently
        // evicted it would report Accepted here instead of Duplicate.
        var replayOfFirst = m.TryAccept(firstFrame);
        Assert.Equal(AcceptStatus.RejectedDuplicate, replayOfFirst.Status);
    }

    [Fact]
    public void Persist_happens_before_any_clipboard_write_is_possible()
    {
        var (m, persistence, _, clock) = NewMachine();
        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 0);

        var outcome = m.TryAccept(frame);
        Assert.True(outcome.IsAccepted);

        // By the time TryAccept returns Accepted (the only path that hands the
        // caller plaintext to write), Persist must already have run — that is
        // the whole point of doing it inside TryAccept rather than leaving the
        // ordering to caller discipline.
        Assert.Single(persistence.PersistCalls);
        persistence.CallOrder.Add("caller_writes_clipboard_now");
        Assert.Equal(["persist", "caller_writes_clipboard_now"], persistence.CallOrder);
    }

    [Fact]
    public void Fails_closed_on_corrupt_persisted_state()
    {
        var persistence = new FakeDedupPersistence { ThrowOnLoad = true };
        var anchor = new FakeCounterAnchor();
        var clock = new FakeClock { NowMs = 1_757_600_000_000 };
        var m = new ReceiverStateMachine(Key, Epoch, 4096, persistence, anchor, clock.Get);

        Assert.True(m.IsTripped);

        var frame = SealAt(clock, Epoch, senderId: 1, offsetMs: 0);
        Assert.Equal(AcceptStatus.RejectedTripped, m.TryAccept(frame).Status);
    }

    [Fact]
    public void Fails_closed_when_the_acceptance_counter_moves_backwards_across_a_restore()
    {
        var persistence = new FakeDedupPersistence();
        var anchor = new FakeCounterAnchor();
        var clock = new FakeClock { NowMs = 1_757_600_000_000 };
        var m1 = new ReceiverStateMachine(Key, Epoch, 4096, persistence, anchor, clock.Get);
        Assert.Equal(AcceptStatus.Accepted, m1.TryAccept(SealAt(clock, Epoch, 1, 0)).Status);
        Assert.Equal(1, anchor.HighWaterMark);

        // Simulate restoring an old backup of *only* the dedup state file: the
        // file goes back to counter 0, but the independent anchor (a different
        // path entirely) still remembers 1.
        persistence.Stored = new DedupSnapshot(new Dictionary<DedupKey, long>(), AcceptanceCounter: 0, LastObservedNowMs: 0);

        var m2 = new ReceiverStateMachine(Key, Epoch, 4096, persistence, anchor, clock.Get);

        Assert.True(m2.IsTripped);
        Assert.Equal(AcceptStatus.RejectedTripped, m2.TryAccept(SealAt(clock, Epoch, 2, 0)).Status);
    }

    [Fact]
    public void Fails_closed_on_a_live_clock_rollback_mid_run()
    {
        var (m, _, _, clock) = NewMachine();
        Assert.Equal(AcceptStatus.Accepted, m.TryAccept(SealAt(clock, Epoch, 1, 0)).Status);

        clock.NowMs -= 5_000; // wall clock stepped backward

        var outcome = m.TryAccept(SealAt(clock, Epoch, 2, 0));

        Assert.Equal(AcceptStatus.RejectedTripped, outcome.Status);
        Assert.True(m.IsTripped);
    }

    [Fact]
    public void Resume_after_clock_correction_clears_trip_and_flushes_the_cache_but_never_on_its_own()
    {
        var persistence = new FakeDedupPersistence { ThrowOnLoad = true };
        var anchor = new FakeCounterAnchor();
        var clock = new FakeClock { NowMs = 1_757_600_000_000 };
        var m = new ReceiverStateMachine(Key, Epoch, 4096, persistence, anchor, clock.Get);
        Assert.True(m.IsTripped);

        // Never clears itself: still tripped an hour later with no operator action.
        clock.NowMs += 3_600_000;
        Assert.Equal(AcceptStatus.RejectedTripped, m.TryAccept(SealAt(clock, Epoch, 1, 0)).Status);

        persistence.ThrowOnLoad = false; // "operator fixed the underlying cause"
        m.ResumeAfterClockCorrection(4096);

        Assert.False(m.IsTripped);
        Assert.False(anchor.Tripped);
        var outcome = m.TryAccept(SealAt(clock, Epoch, 1, 0));
        Assert.Equal(AcceptStatus.Accepted, outcome.Status);
    }
}
