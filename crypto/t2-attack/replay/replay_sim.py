#!/usr/bin/env python3
"""
T2 PoC: SPEC.md §5's dedup RETENTION window is shorter than §4 step 5's
ACCEPTANCE window, so a malicious relay replays an authentic frame by doing
nothing but waiting.

Receiver below implements SPEC.md §4 steps 1-7 and §5 literally. Crypto is
elided (the frames are authentic -- the relay captured them, it forges nothing).
"""

ACCEPT_WINDOW_MS = 60_000          # SPEC.md §4 step 5: |now - timestamp_ms| > 60_000
RETENTION_MS     = 60_000          # SPEC.md §5: "60 s plus allowed clock skew"
                                   # ^ the skew allowance IS the +-60s of step 5;
                                   #   the spec never states a number, so 60s is
                                   #   the reading an implementer lands on.

class Receiver:
    def __init__(self, retention_ms=RETENTION_MS, capacity=4096):
        self.cache = {}            # (epoch, sender, event_id) -> expiry (receiver ms)
        self.retention = retention_ms
        self.capacity = capacity
        self.epoch = 1
        self.clipboard = []
        self.failed_closed = False

    def _gc(self, now):
        for k, exp in list(self.cache.items()):
            if exp <= now:
                del self.cache[k]

    def deliver(self, frame, now):
        """frame = dict(version, epoch, sender, event_id, ts, plaintext)"""
        if self.failed_closed:
            return "fail_closed"
        self._gc(now)
        if frame["version"] != 1:                      # §4.2
            return "bad_version"
        if frame["epoch"] != self.epoch:               # §4.3
            return "stale_epoch"
        # §4.4 decrypt+verify -- authentic, the relay replayed a real frame
        if abs(now - frame["ts"]) > ACCEPT_WINDOW_MS:  # §4.5
            return "stale_timestamp"
        k = (frame["epoch"], frame["sender"], frame["event_id"])
        if k in self.cache:                            # §4.6
            return "duplicate"
        if len(self.cache) >= self.capacity:           # §5 reject-when-full
            return "cache_full"
        self.cache[k] = now + self.retention           # §4.7 persist, then...
        self.clipboard.append(frame["plaintext"])      # ...write clipboard
        return "ACCEPTED"

    def clock_jump_forward(self, now, by_ms):
        """A tainted NTP answer on the tailnet. Entries hold ABSOLUTE expiries."""
        self._gc(now + by_ms)
        return now + by_ms


def frame(ts, event_id="e1", pt="sk_live_51H8fQ...API_KEY"):
    return dict(version=1, epoch=1, sender=0x10000001, event_id=event_id, ts=ts, plaintext=pt)


def scenario(title, sender_skew_ms, replay_delays):
    print(f"--- {title}")
    r = Receiver()
    t0 = 1_000_000
    # Sender's clock is ahead by sender_skew_ms; it stamps the frame accordingly.
    f = frame(ts=t0 + sender_skew_ms)
    print(f"    sender clock ahead by {sender_skew_ms/1000:>5.0f}s   frame.timestamp_ms = now+{sender_skew_ms}")
    print(f"    t+  0.0s  relay delivers original            -> {r.deliver(f, t0)}")
    for d in replay_delays:
        res = r.deliver(f, t0 + d)
        flag = "  <<< REPLAYED, CLIPBOARD WRITTEN AGAIN" if res == "ACCEPTED" else ""
        print(f"    t+{d/1000:>5.1f}s  relay re-delivers the SAME frame   -> {res}{flag}")
    print(f"    clipboard writes: {len(r.clipboard)}\n")


print("=" * 74)
print("PoC R1 -- retention (60s) < acceptance window (up to 120s)")
print("=" * 74)
scenario("baseline: clocks in sync -- spec holds", 0, [30_000, 61_000, 90_000])
scenario("sender clock 45s ahead (within the spec's own +-60s tolerance)",
         45_000, [30_000, 61_000, 90_000, 104_000, 106_000])
scenario("sender clock 59s ahead", 59_000, [61_000, 100_000, 118_000, 120_000])

print("=" * 74)
print("PoC R2 -- tailnet NTP pushes the receiver's clock forward")
print("=" * 74)
r = Receiver()
t0 = 1_000_000
f = frame(ts=t0)
print(f"    t+ 0s   original delivered                 -> {r.deliver(f, t0)}")
print(f"    t+10s   replay                             -> {r.deliver(f, t0 + 10_000)}")
print("    t+10s   attacker-controlled NTP steps the receiver clock +61s")
now = r.clock_jump_forward(t0 + 10_000, 61_000)
print(f"            dedup cache entries surviving the jump: {len(r.cache)}")
print(f"    t+71s   replay after the jump              -> {r.deliver(f, now)}")
print("            (rejected only because step 5 now sees the frame as stale --")
print("             the dedup cache contributed nothing. Combine with a sender")
print("             whose clock is also ahead and step 5 stops covering for it:)")
r2 = Receiver()
f2 = frame(ts=t0 + 55_000, event_id="e2")
print(f"\n    t+ 0s   original (sender 55s ahead)         -> {r2.deliver(f2, t0)}")
print("    t+ 1s   NTP steps the receiver clock +61s")
now2 = r2.clock_jump_forward(t0 + 1_000, 61_000)
print(f"            dedup entries surviving: {len(r2.cache)}")
res = r2.deliver(f2, now2)
print(f"    t+62s   replay                             -> {res}"
      + ("  <<< REPLAYED" if res == "ACCEPTED" else ""))

print()
print("=" * 74)
print("PoC R3 -- can the untrusted relay exhaust the dedup cache?")
print("=" * 74)
r = Receiver(capacity=8)
t0 = 1_000_000
real = frame(ts=t0, event_id="real")
print(f"    relay delivers 1 authentic frame          -> {r.deliver(real, t0)}")
for i in range(500):
    r.deliver(real, t0 + 1)                       # replays
print(f"    ...then replays it 500 times. cache size  -> {len(r.cache)}")
forged = dict(real, event_id="forged")            # would fail step 4 in reality
print("    relay cannot mint new (epoch,sender,event_id) entries: step 7 is")
print("    only reached AFTER tag verification, and it holds no key.")
print("    => cache exhaustion by the relay alone: NOT POSSIBLE. Spec is right here.")

print()
print("=" * 74)
print("PoC R4 -- the crash window makes §5's retry rule a guaranteed dead end")
print("=" * 74)
r = Receiver()
t0 = 1_000_000
f = frame(ts=t0, event_id="totp-1", pt="012345")
# §4 step 7: persist the dedup entry, THEN write the clipboard.
r._gc(t0)
k = (f["epoch"], f["sender"], f["event_id"])
r.cache[k] = t0 + r.retention
print("    t+0s   receiver persists the dedup entry (§4 step 7, first half)")
print("    t+0s   *** agent crashes before the clipboard write ***")
print("    t+2s   sender retries. §5: 'A retry reuses the original event_id,")
print("           nonce and ciphertext -- the identical frame.'")
print(f"    t+2s   identical frame re-delivered          -> {r.deliver(f, t0 + 2_000)}")
print(f"    clipboard writes: {len(r.clipboard)}")
print("    The retry mechanism §5 prescribes cannot ever recover this delivery.")
print("    For a 30s TOTP code that is the whole point of the product failing,")
print("    silently, and §5 describes it as 'may lose a delivery'.")

print()
print("=" * 74)
print("PoC R5 -- §5 'fail closed' is an unrecoverable DoS with no exit")
print("=" * 74)
r = Receiver()
r.failed_closed = True    # triggered by corrupt cache state or clock rollback
print(f"    receiver detected clock rollback -> fail closed")
for d in (0, 60_000, 86_400_000):
    print(f"    t+{d//1000:>6}s  legitimate frame                 -> {r.deliver(frame(ts=1_000_000 + d, event_id=f'x{d}'), 1_000_000 + d)}")
print("    SPEC.md specifies no recovery procedure. A tailnet attacker who can")
print("    answer NTP can step any receiver's clock backwards and brick it.")
