# T2 — Adversarial pass on the BatonPass envelope

**Target:** `crypto/SPEC.md` v1 (frozen), `crypto/vectors.json` (12 vectors),
`crypto/ref-swift/main.swift`, `crypto/ref-csharp/Program.cs`.
**Adversary model used:** exactly the one in `PLAN.md` §2–3 — untrusted relay
(sees, drops, reorders, delays, duplicates, replays every frame; serves hostile
JS from its own pages), plus an unenrolled network attacker on the tailnet.
Sender-ID forgery by a keyholder is **accepted, not a finding** (see F0).

**PoCs:** `crypto/t2-attack/` — see its README for how to run each one.

**Verdict: T1 must be revised before T4, T5 and T6 start.** Three of the top
four findings are wrong constants or unspecified arithmetic *in normative text*,
and T4/T6 are delegated to bounded workers whose instruction is "SPEC.md is
normative, vectors.json is the contract". They will copy the bugs verbatim, and
the vector suite cannot catch any of them.

---

## Summary table

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | **High** | Dedup retention (60 s) is shorter than the acceptance window (up to 120 s) — the relay replays an authentic frame by waiting | **Demonstrated** |
| F2 | **High** | §3/§4 state min frame = 49; the true minimum is 61. Lengths 49–60 underflow the ciphertext span | **Demonstrated** (crash, both languages) |
| F3 | **High** | §4 step 5 specifies `\|now - timestamp_ms\|` over a `uint64` field. Swift traps; C# silently rejects all clock-ahead senders | **Demonstrated** (SIGTRAP + logic inversion) |
| F4 | **High** | Rekey moved through the clipboard delivers the new key to the device being revoked | Reasoned |
| F5 | **Medium-High** | Restore-from-backup rolls back dedup state and epoch; §5 fails closed on *corrupt* state, not on *stale* state | Reasoned |
| F6 | **Medium** | §7's headline claim is false; the vector suite covers the AEAD and **zero** of §4 steps 3/5/6/7 | **Demonstrated** |
| F7 | **Medium** | §1 and §6 contradict each other on persisted counters; the key-use budget is per-*epoch*, not per-*key*, and is unenforceable as described | Reasoned |
| F8 | **Medium** | No normative requirement on CSPRNG failure for nonce/`event_id`; no reference code and no vector for the one operation that can destroy the system | Reasoned |
| F9 | **Medium** | Tailnet NTP: forward step flushes the dedup cache; backward step bricks the receiver with no specified recovery | **Demonstrated** (sim) |
| F10 | **Low-Medium** | Step 3 rejects on an unauthenticated field before crypto — timing oracle for the current epoch and for which device failed to rekey | Reasoned |
| F11 | **Low-Medium** | The §5 crash window makes the §5 retry rule a guaranteed dead end, not a "may" | **Demonstrated** (sim) |
| F12 | **Low** | §3 delegates the frame cap to "the transport" without making it normative in T3/T4 | Reasoned |
| F13 | **Low** | Dedup cache capacity is unspecified, yet §5 mandates reject-when-full | Reasoned |
| F14 | **Low** | Sender behaviour above the 65,536-byte limit is unspecified (truncate vs reject) | Reasoned |
| F15 | **Low** | Reference hex parsers force-unwrap / throw on malformed input | Reasoned |

---

## F0 — Sender-ID forgery by a keyholder: accepted, not fixed

Required by T2's acceptance criteria, so stated explicitly. `sender_id` is a
plaintext header field authenticated only by a key every enrolled device holds.
Any keyholder can set it to any value. There is **no fix at this layer** short of
per-device keys and per-device signatures, which contradicts the settled trust
model ("all enrolled devices equally trusted; the mitigation for an untrusted
device is non-enrollment"). `sender_id` is dedup and routing metadata. Confirmed
as designed; not counted as a finding.

One consequence worth writing down: a **cloned VM or a device provisioned twice
from the same key material shares its `sender_id`**. That does not break dedup
(`event_id` is 128 random bits, so collision is ~2^-128), but it does mean the
per-peer receive toggles in `PLAN.md` §3.8 / T4 cannot distinguish the clone from
the original. Those toggles are already documented as convenience, not a
boundary. Keep it that way in T4's UI copy.

---

## F1 — Replay of an authentic frame, from clock skew alone. **High. Demonstrated.**

### The vulnerability

Two windows in the spec disagree, and the smaller one is the one that protects you.

- §4 step 5 accepts a frame while `|now - timestamp_ms| <= 60_000`. That is a
  **±60 s** test, so a frame stamped `ts` is acceptable during the receiver-clock
  interval `[ts - 60s, ts + 60s]` — **120 seconds wide**.
- §5 retains the dedup entry for "60 s plus allowed clock skew". The skew
  allowance *is* the ±60 s of step 5; §5 names no number. The reading an
  implementer lands on is 60 s from acceptance.

If the sender's clock is ahead of the receiver's by Δ, the frame is accepted at
receiver-time `t0` but stays step-5-acceptable until `ts + 60s = t0 + Δ + 60s`,
while its dedup entry dies at `t0 + 60s`. **That is a Δ-second window in which
the identical authentic frame is accepted a second time.**

The relay needs no key, no forgery and no clock control. It captures a frame,
holds it, and re-sends it. Δ is ordinary unsynchronised clock skew between an
iPhone and a Windows PC — the spec tolerates ±60 s precisely because it expects it.

### Exploitation

`crypto/t2-attack/replay/replay_sim.py`, PoC R1. The receiver implements §4
steps 1–7 and §5 literally.

```
--- sender clock 45s ahead (within the spec's own +-60s tolerance)
    t+  0.0s  relay delivers original            -> ACCEPTED
    t+ 30.0s  relay re-delivers the SAME frame   -> duplicate
    t+ 61.0s  relay re-delivers the SAME frame   -> ACCEPTED  <<< REPLAYED
    t+ 90.0s  relay re-delivers the SAME frame   -> duplicate
    t+106.0s  relay re-delivers the SAME frame   -> stale_timestamp
    clipboard writes: 2
```

With clocks in sync the spec holds (baseline scenario passes). The defence fails
on exactly the condition it was built to tolerate.

### Real-world attack scenario

You copy a `sk_live_...` key on the iPhone and paste it into a terminal on
Windows. You then copy something else — a password, a commit message, a
colleague's address. Sixty-one seconds after the first send, the compromised
relay re-delivers the original frame. The Windows agent authenticates it (it is
genuine), finds no dedup entry (it expired), and **overwrites your clipboard with
the API key**. Your next paste puts a live production credential into whatever
field has focus: a Slack message, a Jira ticket, a browser form on a page the
relay itself serves. The relay chooses the moment.

The relay does not need to break anything. It needs a stopwatch.

### Mitigation

Retain each dedup entry until *its own* acceptance window closes, not for a fixed
interval from acceptance:

> Retain the entry until receiver-clock time `max(now_at_acceptance, timestamp_ms)
> + ACCEPT_WINDOW_MS`. With `ACCEPT_WINDOW_MS = 60_000` that is a worst case of
> 120 s, not 60 s.

Then state both numbers as constants in §3's limits table so no implementer has
to infer "plus allowed clock skew". Add a negative vector / conformance case:
*frame stamped `now + 45s`, accepted, replayed at `now + 61s`, must be rejected.*

---

## F2 — The stated minimum frame size is 12 bytes too small. **High. Demonstrated.**

### The vulnerability

§3's limits table and §4 step 1 both say **49**. An empty-plaintext frame is
`header 33 + nonce 12 + tag 16 = 61` bytes. The 49 is `33 + 16` — the nonce was
dropped from the sum.

This is not cosmetic. Both reference implementations, and any implementation
following §2's offsets, compute the ciphertext span as
`frame[45 .. len-16]`, i.e. length `len - 61`. For `49 <= len <= 60` that length
is **negative**.

The vector suite cannot catch it. The only sub-minimum vector, `truncated`, is
**60 bytes** — it sits *inside* the erroneous window. A spec-conformant receiver
does not reject `truncated`; it crashes on it.

### Exploitation

`crypto/t2-attack/cs` A1 — a receiver written to §3/§4 verbatim:

```
=== A1: SPEC.md's stated min frame (49) is 12 bytes short ===
header 33 + nonce 12 + tag 16 = 61  <-- true minimum
SPEC.md §3/§4 say: 49

feeding vectors.json 'truncated' (60 bytes) to a spec-conformant receiver...
  >>> ArgumentOutOfRangeException: Specified argument was out of the range of valid values.

feeding a crafted 49-byte frame (version=0x01, rest zero)...
  >>> ArgumentOutOfRangeException: Specified argument was out of the range of valid values.
```

`crypto/t2-attack/swift` a1 — same frame, Swift:

```
$ ./attack a1
A1: feeding a 49-byte frame to a receiver written to SPEC.md §4 step 1
    (49 >= SPEC_MIN_FRAME, so the length check passes)
   exit=133            # SIGTRAP
```

Note the Swift case is a **range trap, not a Swift error** — the PoC wraps the
call in `try?` and it still dies. No `catch` saves you; the process is gone.

The whole payload is 49 bytes: `01` followed by 48 zeros.

### Real-world attack scenario

The relay, which holds no key, sends 49 zero-ish bytes to every subscriber. Every
receiver built from the spec dies instantly. On Windows that is the logon-session
agent (T6) — it exits and clipboard sync stops until the user notices and logs
out and in. On iOS (T11) it is a crash on every receive attempt. The relay can
do this on a timer, forever, with a payload smaller than this sentence. It is a
one-packet, zero-knowledge, persistent denial of service against the whole
product, delivered by the component the threat model already designates as
hostile.

Worse, it is a **crash on attacker-controlled input before authentication**, which
in the iOS/macOS agents means a repeatable abort inside a process holding the
group key in memory — the class of primitive you do not want to hand to anyone.

### Mitigation

1. §3: `min frame | **61** bytes (empty plaintext) = 33 header + 12 nonce + 16 tag`.
   Show the arithmetic in the table so it can't silently drift again.
2. §4 step 1: `Reject if len(frame) < 61 or len(frame) > 65_597.`
3. Restate the derivation of every limit alongside its value, so the two places
   the constants appear cannot disagree.
4. Add conformance vectors at **60, 61, 65_597 and 65_598** bytes. The current
   suite has one length vector and it is the wrong length.
5. Independently of the constant: require the ciphertext length to be computed
   and checked as a **signed** quantity, rejecting if negative, so a future
   constant error degrades to a rejection rather than a crash.

The shipped reference code uses `HeaderSize + NonceSize + TagSize` = 61 and is
safe (see "What I could not break"). This bug exists purely as spec-vs-code
divergence — which is exactly why it is dangerous: it will land in T4/T5/T6 and
pass the whole vector suite on its way in.

---

## F3 — `|now - timestamp_ms|` over an unsigned field. **High. Demonstrated.**

### The vulnerability

§2 declares `timestamp_ms` as `uint64`. §4 step 5 says:

> Reject if `|now - timestamp_ms| > 60_000`.

Written in the field's own type, `now - timestamp_ms` is unsigned subtraction, and
step 5 *explicitly permits* `timestamp_ms > now` (the test is two-sided). So the
normative text prescribes an operation that underflows whenever the sender's clock
is ahead — which the ±60 s tolerance exists to accommodate.

The two target languages fail differently, and both failures are bad:

- **Swift:** `UInt64` overflow **traps**. Process abort.
- **C#:** `ulong` wraps silently to ~1.8e19, which is `> 60_000`, so every frame
  from a clock-ahead sender is **rejected**. Fails closed, silently, with no
  diagnostic distinguishing it from a stale frame.

### Exploitation

`crypto/t2-attack/cs` A2:

```
  sender 0ms behind            spec-as-written: accept   intended: accept
  sender 1ms AHEAD             spec-as-written: REJECT   intended: accept   <-- MISMATCH
  sender 1000ms AHEAD          spec-as-written: REJECT   intended: accept   <-- MISMATCH
  sender 30000ms AHEAD         spec-as-written: REJECT   intended: accept   <-- MISMATCH
  sender 59000ms AHEAD         spec-as-written: REJECT   intended: accept   <-- MISMATCH
  sender 1000ms behind         spec-as-written: accept   intended: accept
  sender 61000ms behind        spec-as-written: REJECT   intended: reject
```

`crypto/t2-attack/swift` a2, with the sender's clock **1 ms** ahead:

```
$ ./attack a2
A2: §4 step 5, sender clock 1 ms ahead of receiver
    now = 1757600000000, timestamp_ms = 1757600000001
   exit=133            # SIGTRAP
```

### Real-world attack scenario

Two paths, one of them adversarial.

**Reliability path (no attacker).** Milestone 1 is "copy in Google Authenticator
on iPhone → one Back Tap → paste on Windows". If the iPhone's clock is one
millisecond ahead of the PC's — which it will be, roughly half the time — the
Windows agent rejects every single frame and reports "stale timestamp". You will
spend a day blaming Tailscale.

**Attack path.** Step 5 runs *after* authentication, so the relay cannot reach it
directly. The **unenrolled tailnet attacker can**: NTP is unauthenticated, and the
lab server and the colleague's machine are on the tailnet by design. Answer the
iPhone's or Mac's NTP query, step its clock *backwards*, and the next authentic
frame from any peer has `timestamp_ms > now` — the Swift agent traps. Repeatable
remote abort of a process that holds the group key, triggered by a machine that
was deliberately never enrolled. That is a real boundary crossing: non-enrollment
is supposed to be the mitigation, and here it isn't one.

### Mitigation

1. §4 step 5 must specify the arithmetic, not just the predicate:

   > Convert both values to signed 64-bit milliseconds. Reject if
   > `abs((int64)now - (int64)timestamp_ms) > 60_000`. Implementations **must not**
   > perform this subtraction in the field's unsigned type.

2. Bound the field on parse: reject `timestamp_ms > 2^63 - 1` before any
   arithmetic, so the signed conversion itself cannot trap on a hostile value
   from a keyholder.
3. Add conformance cases at `ts = now - 61s`, `now - 1ms`, `now`, `now + 1ms`,
   `now + 59s`, `now + 61s`. The current suite has one timestamp and never varies
   it (see F6).
4. Tighten the window while you are in there. ±60 s is generous for a tailnet;
   ±30 s halves F1's replay window and still survives normal skew. Then pair it
   with `chrony`/`w32time` on the endpoints and say so in the setup doc.

---

## F4 — Rekey through the clipboard hands the new key to the revoked device. **High. Reasoned.**

### The vulnerability

§6 protects exactly one transport for key material:

> The group key is never typed into a page the relay serves.

It says nothing about the transport the user will actually reach for. §6 step 3
says "import it independently on each retained device", and the product you are
holding is *a tool for moving text between your devices*. The natural motion —
generate the key on the Mac, copy it, Back Tap, paste on Windows — encrypts the
new key **under the old key, at the old epoch**, and hands it to the relay for
fan-out.

The relay fans out to every subscriber. The device you are revoking is still
subscribed (nothing in §6 removes it from the relay's allowlist) and still holds
epoch-N key material (nothing in §6 destroys it). It decrypts the frame carrying
its own replacement key.

Revocation does not just fail. It fails **silently and permanently**, and every
subsequent epoch is compromised too, because the same procedure will be used next
time.

### Exploitation

Not demonstrated — it requires the T4 relay and two agents, none of which exist
yet. It needs no cleverness: it is the documented procedure executed with the
product's own primary feature.

Note the supporting facts are all in the spec already:
- §6 never says "erase the old key on retained devices".
- §6 never says "remove the revoked device from the relay allowlist" — it argues
  the opposite, that relay-side revocation is insufficient, and then omits it
  entirely rather than requiring it *as well*.
- §5 confirms the relay sees every frame. §6 confirms the revoked device holds
  epoch-N key material.

### Real-world attack scenario

You are revoking a laptop you have just sold, or one you think is compromised.
You follow §6 to the letter. The buyer's laptop — or the implant on it — is still
running the agent, still on the tailnet, still subscribed. It receives your new
32-byte key, imports it, and follows you into epoch N+1. You believe you have
revoked it. You have onboarded it.

Since the clipboard "routinely carries API keys and TOTP codes", the attacker now
gets every one of them, indefinitely, with the reassuring knowledge that you
performed a rekey and considered the matter closed.

### Mitigation

Rewrite §6's rekey procedure with explicit negative requirements:

1. **The group key MUST NOT be transported by BatonPass.** Add it next to the
   existing "never typed into a page the relay serves" sentence, in bold, with
   the reason. This is the single most important sentence missing from the spec.
2. Specify the permitted import channels concretely: on-device QR scan (iOS
   camera reading a QR rendered on the Mac), or manual keyboard entry of a
   BIP39-style mnemonic. Both are offline and neither touches the relay.
3. Add step 0: **remove the revoked device from the relay allowlist first.**
   The spec is right that this is not sufficient; it is still necessary, and
   right now it isn't in the procedure at all.
4. Add a final step: **destroy epoch-N key material on every retained device.**
   Without it, F5 (state rollback) reopens everything.
5. Make key and epoch a **single atomic record** in Keychain/DPAPI. §6's step 3
   (import key) and step 4 (increment epoch) being separate manual steps means a
   half-rekeyed device is reachable, and its failure mode is "everything is
   rejected at step 3 or step 4 with no diagnostic".

---

## F5 — Restore-from-backup rolls back replay defence and epoch. **Medium-High. Reasoned.**

### The vulnerability

§5 fails closed on "missing or corrupt cache state, and on detected clock
rollback". It does not fail closed on **state rollback** — a dedup cache and
epoch counter that are internally consistent, uncorrupted, and simply *old*.

That is exactly what a restore-from-backup produces. The restored agent has:
- a dedup cache reflecting the world at backup time,
- a `key_epoch` from backup time,
- the key from backup time,
- a wall clock that is correct (so §5's rollback check does not fire).

Every condition §5 checks is satisfied. Nothing fires.

Meanwhile the relay — the designated adversary — has been recording every frame
since forever, because nothing stops it.

### Exploitation

Reasoned. Two chains:

**Replay reset.** The restored receiver's cache contains none of the events
accepted after the backup. The relay replays frames it captured after the backup
point; those within the acceptance window are accepted as new. Combined with F1
the exploitable set is larger than it looks.

**Revocation reversal.** A retained device restored from a pre-rekey backup comes
back at epoch N with key N. It now rejects the current epoch-N+1 traffic (visible
breakage, fine) — but it *accepts* epoch-N traffic, which the revoked device can
still produce, because F4 left it holding key N and §6 never destroyed it. The
revoked device gets a live channel back into the fleet, gated only on the user
restoring a backup.

### Mitigation

1. **Store dedup state and the key/epoch record outside backup scope.**
   iOS/macOS: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — the
   `...ThisDeviceOnly` suffix is the load-bearing part, it excludes the item from
   encrypted backups and from migration to a new device. Windows: DPAPI
   `CurrentUser` scope in a non-roaming, non-backed-up directory. S1 already flags
   Keychain accessibility class as an open question; settle it here, as a
   security requirement, not a convenience one.
2. Consequence, stated deliberately: **restoring a device from backup means
   re-enrolling it.** Missing state then triggers §5's existing fail-closed path,
   which is correct. Write it in §6 as a procedure.
3. Persist a **monotonic acceptance counter** alongside the dedup cache. On start,
   if the counter is lower than the highest value ever observed by that device's
   own record, treat it as rollback and fail closed — the same way §5 already
   treats clock rollback. This catches restore even if (1) is implemented wrong.
4. §5 currently reads "missing or corrupt". Change to "**missing, corrupt, or
   older than the last state this device wrote**".

---

## F6 — §7's headline claim is false, and the suite tests only the AEAD. **Medium. Demonstrated.**

### The claim

> The `tampered_header` vector is the one that matters most: it is the only thing
> proving the AAD is genuinely bound, and a broken AAD implementation passes every
> other vector in the file.

Both halves are wrong.

### Exploitation

`crypto/t2-attack/cs` A3, decrypting the **positive** vector `basic` under a
range of broken AAD constructions:

```
  positive vector 'basic' with AAD omitted entirely         -> rejected
  positive vector 'basic' with AAD = version byte only      -> rejected
  positive vector 'basic' with AAD = header minus version   -> rejected
  positive vector 'basic' with AAD = header + nonce (45B)   -> rejected
  positive vector 'basic' with AAD = whole frame            -> rejected
```

The AAD is an input to the tag, so any AAD other than the correct 33 bytes fails
the *positive* vectors. And `ref-csharp`'s re-seal check pins the sender side
byte-exactly. `tampered_header` is a fine regression test; it is not load-bearing
and it is not the thing that matters most. A spec that tells the implementer
which test to care about should point at the right one.

### What the suite actually fails to cover

This is the finding worth acting on. All 12 vectors share **one header**:

```
  distinct header bodies across all vectors (excl. version byte): 2
  => no vector varies epoch, sender_id or timestamp at all.
```

(The 2 are the genuine header and `tampered_header`'s one-bit flip.) Every vector
uses `epoch=1`, `sender=0x10000001`, `ts=1757600000000`, the same `event_id`, the
same nonce.

Consequently the suite exercises **§4 step 4 and nothing else**. There is no
vector for step 3 (epoch), step 5 (timestamp), step 6 (dedup) or step 7 (persist
ordering). The entire replay, epoch and freshness defence — the part of this
system that is actually novel, that F1/F2/F3/F5 all live in, and that is being
**delegated to Spark and Sonnet** with "the vectors are the contract" — has zero
conformance coverage.

To answer the question directly: **no header mutation escapes the tag.** Any
change to bytes `[0,33)` fails authentication, and `tampered_nonce` confirms the
nonce is covered too (the Poly1305 key is derived from key+nonce, so the spec's
reasoning for leaving the nonce out of the AAD is correct). The gap is not in the
AAD. It is that the suite stops at the AEAD boundary and the spec claims the
contract extends further.

### Nothing security-relevant is outside the AAD

Checked and clean. Version, epoch, event_id, sender_id, timestamp are all inside.
The nonce is outside but covered by the tag. Ciphertext length is implicit in the
AEAD. There is no recipient field and no channel binding, but with a single group
key and broadcast fan-out neither would carry meaning. If T3 ever introduces
per-topic routing, the topic must go into the AAD — note it now so the version
bump is anticipated.

### Mitigation

1. Delete the §7 paragraph about `tampered_header` and replace it with: *the
   positive vectors plus the re-seal check prove AAD binding on both sides;
   `tampered_header` is a regression guard.*
2. Add vectors varying **each header field independently**: a second epoch, a
   second `sender_id`, a second timestamp, a `sender_id` of `0x00000000` and
   `0xFFFFFFFF`, an `event_id` of all zeros and all ones. Endianness and field-
   offset bugs currently have exactly one value each to hide behind.
3. Add the length boundary vectors from F2 (60, 61, 65_597, 65_598).
4. Extend `vectors.json` with a **behavioural** section that is not frame bytes:
   ordered `(now, frame)` sequences with expected accept/reject verdicts,
   covering step 3, step 5 and step 6 including the F1 replay case. Both agents
   must run it. Right now T6's acceptance test "replays are rejected" has no
   fixture behind it.

---

## F7 — The nonce argument and the key-use budget. **Medium. Reasoned.**

### What is correct

The arithmetic is right. Collision probability after `n` messages with random
96-bit nonces is `~n(n-1)/2 / 2^96 ≈ n²/2^97`; `n = 2^20` gives `2^-57` and
`n = 2^32` gives `2^-33`, matching the table. NIST SP 800-38D's bound of `2^32`
invocations for random 96-bit IVs is stated accurately. The **decision to use
IETF ChaCha20-Poly1305 instead of `PLAN.md` §3.1's XChaCha20 is justified** and
I am not arguing with it: vendoring libsodium into an iOS App Intent and a
Windows agent to buy margin this system cannot consume is a worse trade. This
deviation should stand.

The choice of **random nonces over counters is also right**, and for a reason the
spec undersells: it makes the budget counter non-security-critical. A counter
would make cold-start persistence a catastrophic-failure surface on the one
platform (iOS) that cold-starts every invocation.

### What is wrong as written

**(a) §1 and §6 contradict each other.** §1 argues persisted counter state is
"exactly the fragility to avoid" and closes with nonces being "stateless across
launches". §6 then mandates "persisted per-device quotas" — a persisted counter
that must be written on every send, from a cold-started iOS app, possibly while
the Keychain is inaccessible. The spec rejects the mechanism in §1 and requires
it in §6.

**(b) The budget is not enforceable as described.** For the quota to mean
anything it must be incremented *and durably persisted* before the frame goes out,
on every send. A crash between increment and send over-counts; a crash between
send and increment under-counts; a restore-from-backup or a VM clone rewinds it
wholesale; two devices provisioned from the same key material each believe they
own their whole quota. §6 says "a device that exhausts its quota stops sending and
reports it" but never says what a device does when the quota record is **missing**.
Fail closed bricks sending on the platform where Keychain access is conditional.
Fail open makes the budget decorative. The spec does not choose.

**(c) The budget is per *epoch*, not per *key*.** §1 says "the existing budget
enforces the safety condition exactly". The safety condition is on encryptions
**under one key**. Nothing in §6 binds an epoch increment to a fresh key — and
§6's own logic ("a device that is not rekeyed is thereby revoked") invites a user
to bump the epoch *as a revocation action* without generating a new key. Do that
twice and you have authorised `2^33` encryptions under one key.

### Why this is Medium and not High

Because of the random-nonce choice, a rewound or lost counter causes **budget
overrun, not nonce reuse**. At the spec's own 200 copies/day, `2^32` is 58,000
years; you will not approach the bound by accident, and a doubled budget takes you
from `2^-33` to `2^-31`. The system is safer than its own argument. That is worth
saying plainly rather than dressing up.

### Mitigation

Simplify rather than harden — the mechanism is not buying what §1 claims:

1. Replace "persisted per-device quotas" with a **best-effort per-device send
   counter used for observability only**, explicitly not a security control, that
   fails *open* (sends proceed) and logs a warning if it cannot be persisted.
   Alarm at `2^24` per device. This removes a per-send durable write from the iOS
   cold-start path, which is a reliability win as well.
2. State the real invariant in §6 as a hard rule:
   **"A `key_epoch` increment MUST accompany a new 32-byte key. The two are one
   atomic record. Bumping the epoch without a new key is forbidden."** That single
   sentence is what actually makes the budget per-key, and it also closes half of
   F4's half-rekey problem.
3. Remove §1's "no additional mechanism is required" claim; it is what makes the
   contradiction with §6 load-bearing. Say instead: *nonces are random, so the
   budget is a monitoring bound, not a correctness dependency.*

---

## F8 — No normative requirement on CSPRNG failure. **Medium. Reasoned.**

### The vulnerability

§1 and §2 say nonces and `event_id` come "from the OS CSPRNG" and name
`SecRandomCopyBytes` and `RandomNumberGenerator`. That is the entire requirement.

`SecRandomCopyBytes` returns an `OSStatus`. The idiom that ignores it leaves the
buffer at whatever it was initialised to — typically **all zeros**:

```swift
var nonce = [UInt8](repeating: 0, count: 12)
_ = SecRandomCopyBytes(kSecRandomDefault, 12, &nonce)   // return discarded
```

A constant nonce across every send is total, immediate compromise: two messages
under one key-nonce pair leak `P1 XOR P2`, and Poly1305 key recovery follows,
giving an attacker who never held the key the ability to **forge frames**. That
is the one failure that takes this system from "relay sees opaque blobs" to
"relay writes arbitrary text into your clipboard".

An all-zero `event_id` is milder but ugly: every frame collides on
`(epoch, sender_id, event_id)`, so the second clipboard item within 60 s is
silently swallowed as a duplicate. You would diagnose that as a flaky network for
a week.

Notably, **`PLAN.md` §3.1 carried this warning** — "never seed from time; never
reset an application PRNG per invocation (cold-started iOS clients make this a
live risk, not a theoretical one)" — and SPEC.md dropped it. It is the one
requirement from the plan that got lost in the rewrite, and it is the most
dangerous one.

Compounding it: **neither reference implementation generates a nonce.** Both use
the fixed vector nonce, correctly, because vectors must be reproducible. So the
single operation that can destroy the system has no reference code, no vector, and
no normative text beyond the name of an API.

### Mitigation

1. Add to §1, normatively:

   > Nonce and `event_id` MUST come from the OS CSPRNG on every encryption. The
   > return status of `SecRandomCopyBytes` MUST be checked; on any failure the
   > send MUST be abandoned and surfaced as an error. Userspace PRNGs
   > (`arc4random_buf` is acceptable; `Random.shared`, `System.Random`,
   > time-seeded or per-invocation-reseeded generators are not) MUST NOT be used.
   > A nonce MUST NOT be derived from the timestamp, the event ID, or the
   > plaintext.

2. Require a **self-check on every send**: reject an all-zero nonce and an
   all-zero `event_id` before sealing. Cheap, catches the exact failure mode, and
   the false-positive rate is `2^-96`.
3. Add a non-vector conformance requirement: *1,000 consecutive sends must produce
   1,000 distinct nonces and 1,000 distinct event IDs.* T5 and T6 each run it once.
   This cannot be a frame vector, which is precisely why it must be written down.

---

## F9 — Tailnet NTP against the dedup cache and the fail-closed rule. **Medium. Demonstrated (sim).**

### The vulnerability

Both directions of a clock step are attacker-useful, and the unenrolled tailnet
machines can answer NTP.

**Forward step** expires the whole dedup cache at once. Entries hold absolute
expiry times; step the clock forward past them and every record is garbage-
collected while the frames they protect are still within step 5's acceptance
window — if the sender's clock is also ahead. That is F1 without waiting.

**Backward step** trips §5's "fail closed on detected clock rollback". §5
specifies the trip and **not the reset**. There is no recovery procedure anywhere
in the spec.

### Exploitation

`crypto/t2-attack/replay/replay_sim.py` PoC R2:

```
    t+ 0s   original (sender 55s ahead)         -> ACCEPTED
    t+ 1s   NTP steps the receiver clock +61s
            dedup entries surviving: 0
    t+62s   replay                             -> ACCEPTED  <<< REPLAYED
```

PoC R5:

```
    receiver detected clock rollback -> fail closed
    t+     0s  legitimate frame                 -> fail_closed
    t+    60s  legitimate frame                 -> fail_closed
    t+ 86400s  legitimate frame                 -> fail_closed
```

### Real-world attack scenario

The colleague's machine and the shared lab server are on the tailnet and
deliberately not enrolled — non-enrollment is the stated mitigation for an
untrusted device. Neither holds the key, and neither needs it. A compromised host
on the tailnet answers the Mac's or the Windows box's NTP query. Backwards: the
receiver bricks itself, silently, permanently, and the documented mitigation for
an untrusted tailnet device turns out not to cover it. Forwards, in concert with
the relay: F1's replay without the 61-second wait.

### Mitigation

1. Drive expiry from a **monotonic clock** (`CLOCK_MONOTONIC` /
   `ContinuousClock` / `Environment.TickCount64`), never wall time. Wall time is
   used only for step 5's comparison against `timestamp_ms`; retention is a
   duration and must not be steerable by NTP.
2. Define "detected clock rollback" numerically — e.g. wall clock moves backwards
   by more than 5 s relative to monotonic elapsed time — so it does not fire on
   routine NTP slew.
3. **Specify the recovery.** Fail-closed must be an explicit, visible, operator-
   clearable state: log it, surface it in the agent UI, and require a deliberate
   user action to resume. "Refuse forever with no way out" is a DoS the spec
   mandates against itself.
4. Setup doc: point the endpoints at an authenticated or pinned time source, or at
   minimum at a source that is not reachable from the tailnet.

---

## F10 — Step 3 rejects on an unauthenticated field, before crypto. **Low-Medium. Reasoned.**

§4 step 3 rejects a stale `key_epoch` before step 4 authenticates anything. As a
reject-only decision on a constant comparison this is defensible, and I could not
turn it into memory unsafety or a decryption bypass.

Two real consequences remain:

**(a) It is an epoch oracle.** Step 3 short-circuits before any crypto; step 4
does ChaCha20-Poly1305 work. The relay takes a captured frame, rewrites the epoch
field to a candidate `E`, and sends it. A fast rejection means `E != current`; a
slow one means `E == current` and the frame reached the AEAD. The relay reads the
receiver's current epoch in a handful of probes. Epoch is not secret, but the
oracle tells the relay **exactly when each device completed a rekey** — and
therefore which device is still on the old epoch. That is how it identifies the
device you failed to rekey, i.e. the one holding stale key material, i.e. the one
to attack. It also tells it when to stop bothering with captured epoch-N frames.

**(b) It is a landmine for the next version.** §4 step 3 as written is safe only
because exactly one epoch is live. T4 and T11 will want a rollover grace period
(accept N and N-1 briefly) the first time a rekey goes wrong mid-flight. The
moment two epochs are live, step 3 becomes **key selection driven by an
unauthenticated attacker-controlled field** — a downgrade primitive where the
relay pins every receiver to the older key by rewriting one byte.

### Mitigation

1. Make the single-live-epoch rule explicit and normative *now*, while it is
   still free: *exactly one `key_epoch` is accepted at any moment. A grace period
   accepting multiple epochs is forbidden in v1 and requires a version bump.*
2. Treat epoch mismatch and authentication failure identically in timing, logging
   and any relay-visible response: one generic "rejected" with no reason code on
   the wire. Reasons go to the local log only. This also closes the accepted /
   duplicate / auth-failed distinction the relay could otherwise use as a
   per-device delivery confirmation.
3. Note in §4 that steps 1–3 operate on unauthenticated input **by design** and
   must therefore be restricted to constant comparisons and length arithmetic —
   no allocation sized by header contents, no state lookup, no key selection.

---

## F11 — The crash window makes the §5 retry rule a dead end. **Low-Medium. Demonstrated (sim).**

§5's ordering is **correct** and I am not arguing with the tradeoff — persisting
before the clipboard write is the right call, and "losing a clipboard item is an
annoyance, replaying an API key is a vulnerability" is the right instinct.

The description is wrong, though. §5 says a crash "**may** lose a delivery", and
separately says a retry reuses the identical frame within the 60 s window. Put
together: after a crash in the window, the dedup entry is already persisted, so
the prescribed retry is **guaranteed** to be rejected as a duplicate. The retry
mechanism cannot recover the exact failure it exists for.

`crypto/t2-attack/replay/replay_sim.py` PoC R4:

```
    t+0s   receiver persists the dedup entry (§4 step 7, first half)
    t+0s   *** agent crashes before the clipboard write ***
    t+2s   identical frame re-delivered          -> duplicate
    clipboard writes: 0
```

Practical consequence: a 30-second TOTP code is lost with no error anywhere, and
the sender's retry logic reports success. T6's acceptance criterion — "a mid-write
crash cannot produce duplicate delivery" — passes while the feature silently
fails. The user's recovery is to re-copy (producing a fresh `event_id`), which
works, so this will never be diagnosed; it will just feel unreliable.

### Mitigation

1. Say it accurately in §5: *a crash in this window **permanently** loses that
   delivery for that receiver; the prescribed retry will be rejected as a
   duplicate. This is intentional.*
2. Persist a two-state record: `{accepted, written}`. On startup, an `accepted`
   entry with no `written` marker is reported to the user as a lost delivery. Do
   **not** use it to permit a retry — that reopens replay. Visibility only.
3. Sender guidance: after `2 × retry-deadline` with no confirmation, tell the
   user the send failed and to re-copy. Do not silently report success.

---

## F12–F15 — Lower-severity gaps

**F12 (Low) — the frame cap is not normative where it is enforced.** §3 says
"Check the length before allocating anything" and then "The transport frames it."
But the relay is the fan-out point and the relay is untrusted. If T4's Phoenix
channel accepts a multi-megabyte blob, every receiver allocates and buffers it
before it can apply §4 step 1. **T3 must make `65_597` a normative transport-level
maximum** (`max_frame_size` on the socket, plus a channel-level check) and SPEC.md
§3 should say so instead of delegating to an unnamed "transport".

**F13 (Low) — dedup cache capacity is unspecified.** §5 mandates reject-when-full
without saying how full is full, which is how you end up with a 256-entry cache
and a self-inflicted outage. Specify a minimum with its derivation: at the spec's
own 200 copies/day and a 120 s retention (per F1), the steady-state occupancy is
well under 10 entries; a **4,096-entry floor** is four orders of magnitude of
headroom and costs ~100 KB. Note explicitly that an entry already in the cache
must **not** have its expiry refreshed on a duplicate hit.

**F14 (Low) — sender behaviour above 65,536 bytes is unspecified.** §3 gives the
receiver's rule and nothing for the sender. `PLAN.md` §3.9 says "reject rather
than fragment"; SPEC.md dropped it. Truncating a UTF-8 payload also splits
multi-byte sequences, and truncating a secret silently is worse than failing.
Add: *a sender MUST reject an over-limit plaintext and surface the error; it MUST
NOT truncate or fragment.* While there, say whether the receiver validates that
the plaintext is well-formed UTF-8 before the clipboard write, and what it does
with an embedded NUL (Windows `CF_UNICODETEXT` truncates at one).

**F15 (Low) — reference hex parsers are unhardened.** `ref-swift`'s `unhex`
force-unwraps `UInt8(_, radix: 16)!` and walks off the end of an odd-length
string; `ref-csharp`'s `Unhex` throws `FormatException` on a non-hex character,
and the verifier dereferences `plaintextHex` on any vector whose `mustReject` is
false. These are test harnesses reading a trusted file, so the severity is
genuinely low — but add a one-line comment saying so, because T5 and T6 will look
at this code as the model and these are the parts not to copy.

---

## What I could NOT break

Listed because it is worth as much as the findings — these are the parts to leave
alone.

1. **The AAD design is right, and the argument for it is right.** "Both sides
   pass a 33-byte slice of the buffer they already hold" genuinely eliminates the
   canonicalization bug class. I tried to make Swift and C# disagree and there is
   nothing to disagree about: no separators, no string formatting, no
   optional fields, no variable-length encoding. The `ref-csharp` re-seal check
   (decrypt proves you read it, reproduce the bytes proves you would write it)
   is a stronger cross-language test than most specs ever get. Keep both.

2. **No header mutation survives the tag.** All 33 header bytes are covered.
   The nonce sits outside the AAD, correctly — the Poly1305 one-time key is
   derived from key+nonce, so nonce tampering fails authentication anyway, and
   `tampered_nonce` demonstrates it. The reasoning in §2 is sound.

3. **The relay cannot exhaust the dedup cache.** PoC R3: step 7 is reachable only
   after tag verification, and the relay holds no key, so it cannot mint new
   `(epoch, sender_id, event_id)` entries. 500 replays of a genuine frame leave
   the cache at size 1. "Reject when full" is therefore **not** a cheap DoS for
   the relay, which was the sharpest form of question 3 and the answer is no.
   Cache growth is bounded by the legitimate send rate over the retention window.

4. **The shipped reference receivers are length-safe.** PoC A4 fuzzed
   `ref-csharp`'s `TryOpen` verbatim: every length 0–80 plus the 65,596/65,597/
   65,598/100,000 boundaries with random content, every single-byte position of a
   genuine frame mutated 8 times, and every truncation and extension.
   **17,889 frames, 0 unhandled exceptions, 0 forgeries** — the 4 acceptances were
   no-op mutations that reproduced the genuine frame byte-for-byte. F2 exists
   purely because the *spec* and the *code* disagree about one constant; the code
   has it right.

5. **The §4 step ordering is correct.** Steps 5 and 6 after step 4 is the right
   call and the spec's justification for it is right — moving either above the
   authentication line would hand the relay a cache-probing oracle. I found no
   reordering that improves anything and no information leak in the ordering
   itself beyond F10's step-3 timing, which is inherent to rejecting early rather
   than to the order.

6. **No downgrade.** `version` is inside the AAD and compared against a hard
   constant with no negotiation. There is nothing to downgrade to.

7. **The cipher choice.** IETF ChaCha20-Poly1305 over `PLAN.md` §3.1's XChaCha20
   is the right trade for this system, the `n²/2^97` derivation is correct, the
   table values are correct, and the NIST `2^32` figure is cited accurately. F7
   is about the *budget mechanism*, not the cipher. Do not revisit the cipher.

8. **Sender-ID forgery by a keyholder** — confirmed unfixable at this layer and
   correctly documented as accepted. See F0.

---

## Recommended revisions to T1, in order

Blocking T4/T5/T6:

1. **F2** — `min frame` 49 → **61** in §3 and §4 step 1, with the arithmetic shown.
2. **F3** — §4 step 5: specify signed 64-bit arithmetic; bound `timestamp_ms`.
3. **F1** — §5: retain until `max(now, timestamp_ms) + 60_000`, and put both
   constants in §3's table.
4. **F4** — §6: "the group key MUST NOT be transported by BatonPass"; add
   allowlist removal as step 0 and old-key destruction as the final step.

Blocking T6 and T8 specifically (the receivers):

5. **F5** — `...ThisDeviceOnly` / non-backed-up storage for dedup and key/epoch;
   fail closed on stale state, not only corrupt state.
6. **F9** — monotonic clock for retention; define rollback numerically; specify
   the fail-closed recovery procedure.
7. **F8** — normative CSPRNG failure handling and the all-zero self-check.

Blocking nothing, but cheap and worth doing in the same pass:

8. **F6** — fix §7's claim; add per-field header vectors, length boundary vectors,
   and a behavioural fixture covering steps 3/5/6.
9. **F7** — demote the quota to observability; state "new epoch ⟺ new key".
10. **F10** — pin the single-live-epoch rule; uniform rejection on the wire.
11. **F11–F15** — wording and the T3 transport cap.

F1, F2 and F3 all pass the entire 12-vector suite. That is the argument for doing
F6 in the same revision rather than deferring it: the contract T4/T5/T6 are being
handed does not currently test the half of the spec that is wrong.
