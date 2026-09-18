# BatonPass envelope — wire specification v1.1

**Status: T1 deliverable, revised after the T2 adversarial review.** Frozen.
Changes require a version bump.

The wire format is unchanged from v1.0 — no frame produced by v1.0 code is
invalid under v1.1. What changed is the normative text around it: three stated
constants and one arithmetic rule were wrong, and every one of them passed the
original conformance suite. See `T2-FINDINGS.md` for the attacks.

This document plus `vectors.json` is the contract. Any implementation that
reproduces the vectors is correct; any that does not is wrong, regardless of how
reasonable its code looks.

---

## 1. Cipher

**IETF ChaCha20-Poly1305** (RFC 8439). 256-bit key, **96-bit nonce**, 128-bit tag.

### Why not XChaCha20, which PLAN.md §3.1 mandated

XChaCha20-Poly1305 exists in neither Swift's CryptoKit nor .NET's
`System.Security.Cryptography`. Mandating it forces libsodium into the iOS app
and the Windows agent — a vendored C dependency on the two platforms where
dependencies are most expensive, to buy a safety margin this system cannot
consume.

Both platforms ship IETF ChaCha20-Poly1305 in their standard libraries, verified
on this machine:

```
Swift CryptoKit ChaChaPoly            → nonce 12 bytes, tag 16 bytes
.NET ChaCha20Poly1305.IsSupported     → True, nonce 12, tag 16
```

**The 96-bit nonce is safe here by an enormous margin.** With nonces drawn from
the OS CSPRNG, collision probability after `n` messages is about `n² / 2^97`.

| messages under one key | collision probability |
|---|---|
| 2^20 (one million) | ~2^-57 |
| 2^32 (four billion) | ~2^-33 |

NIST's bound for random 96-bit nonces is 2^32 invocations per key. **The key-use
budget in §6 is already 2^32 per epoch**, so the existing budget enforces the
safety condition exactly — no additional mechanism is required.

At a realistic 200 clipboard copies per day, 2^32 messages is roughly 58,000
years. The epoch budget will never bind in practice; it exists so that the
invariant is checked rather than assumed.

Random nonces were chosen over counters deliberately: a counter must survive
cold starts, and the iOS client may be cold-started on every single invocation.
Persisted counter state is exactly the fragility to avoid. `SecRandomCopyBytes`
and `RandomNumberGenerator` are stateless across launches.

---

## 2. Frame layout

Binary. All multi-byte integers **big-endian**. No padding, no alignment.

```
offset  size  field
------  ----  -----------------------------------------------------
     0     1  version           = 0x01
     1     4  key_epoch         uint32
     5    16  event_id          128 bits from the OS CSPRNG
    21     4  sender_id         uint32
    25     8  timestamp_ms      uint64, Unix epoch milliseconds
    33    12  nonce             96 bits from the OS CSPRNG
    45     N  ciphertext        N = plaintext length
  45+N    16  tag               Poly1305
```

Header is bytes `[0, 33)`. Total frame length is `45 + N + 16`.

### The AAD is the header, verbatim

**AAD = frame bytes `[0, 33)`.** Not a formatted string. Not a concatenation of
stringified fields. The literal header bytes.

This is the whole reason the layout is shaped this way. Astra's audit required a
"byte-exact canonical encoding (cross-language: Swift and C# must agree)", and
every canonical-encoding bug in this class of protocol comes from two languages
disagreeing about separators, integer formatting, string encoding, or field
order. Here there is nothing to agree about: both sides pass a 33-byte slice of
the buffer they already hold.

The nonce is deliberately **outside** the AAD. It is an input to the AEAD itself
and authenticating it again buys nothing.

Everything the receiver needs in order to decide *whether* to decrypt — version,
epoch, event ID, sender, timestamp — is inside the authenticated header, so a
forged or altered header fails the tag check rather than steering the receiver.

---

## 3. Limits (enforced before allocation)

| limit | value |
|---|---|
| max plaintext | 65,536 bytes |
| **min frame** | **61 bytes** (empty plaintext: 33 header + 12 nonce + 16 tag) |
| max frame | 65,597 bytes (33 + 65,536 + 12 + 16) |

Reject on: frame shorter than 61, frame longer than max, `version != 0x01`.

> Revision v1.1 (T2/F2). This said **49** — the nonce was dropped from the sum.
> Lengths 49–60 passed the check and then produced a **negative** ciphertext
> length. Demonstrated: Swift aborts with SIGTRAP (exit 133), C# throws
> `ArgumentOutOfRangeException`. The reference code always computed 61 and was
> correct; the normative text was wrong, which is worse, because implementers
> follow the text. The `truncated` vector is 60 bytes and sits *inside* the
> hole — a receiver built to the old text does not reject it, it crashes on it.

**Check the length before allocating anything and before decrypting.** A frame
claiming a large size must be rejected on its actual received length, never on a
length field — there is no length field, by design. The transport frames it.

**The relay MUST enforce the 65,597-byte cap itself** and reject oversized
frames without buffering them. It is the fan-out point and it is untrusted;
delegating the cap to "the transport" leaves the one component every frame
passes through with no stated limit. This is normative for T3/T4. (T2/F12.)

**A sender whose plaintext exceeds 65,536 bytes MUST reject the item and report
it. Never fragment.** Fragmentation would require reassembly state on every
receiver and a partial-delivery story this system does not have. (T2/F14.)

---

## 4. Receiver algorithm

Order is normative. Do not reorder for efficiency.

1. Reject if `len(frame) < 61` or `len(frame) > 65597`.
2. Reject if `frame[0] != 0x01`.
3. Reject if `key_epoch` is not the current epoch.
4. **Decrypt and verify the tag.** Nothing below this line may run on
   unauthenticated input.
5. Reject if the frame is outside the freshness window. **Compute this in
   signed 64-bit arithmetic**, or as two separate unsigned comparisons:

   ```
   reject if timestamp_ms > now + 60_000     // sender ahead
   reject if timestamp_ms < now - 60_000     // sender behind
   ```

   **Never compute `now - timestamp_ms` in unsigned arithmetic.** `timestamp_ms`
   is `uint64` and the spec explicitly permits `timestamp_ms > now`, so that
   subtraction underflows. Demonstrated (T2/F3): Swift traps on a frame just
   **1 ms** ahead; C# wraps silently and rejects *every* frame from a
   clock-ahead sender — which presents as "Milestone 1 works about half the
   time" and gets blamed on Tailscale.

   Also reject `timestamp_ms` greater than `now + 60_000` before any further
   arithmetic on it, so a hostile value cannot reach a later calculation.
6. Reject if `(key_epoch, sender_id, event_id)` is already in the dedup cache.
7. **Persist the dedup entry. Then write the clipboard.** In that order — see §5.

Steps 5 and 6 come *after* step 4 deliberately. Timestamp and dedup checks on
unauthenticated input let an attacker probe cache state.

---

## 5. Replay defence

Dedup key: `(key_epoch, sender_id, event_id)`.

- **Persist the acceptance record before writing the clipboard.** A crash
  between the two may lose a delivery; it must never permit a duplicate one.
  Losing a clipboard item is an annoyance. Replaying an API key is a
  vulnerability.
- **Retain each entry until `max(now_at_acceptance, timestamp_ms) + 60_000`.**
  Retaining longer is free; retaining too little is a replay.

  > Revision v1.1 (T2/F1). This said "60 s plus allowed clock skew", which reads
  > as 60 s. But step 5 accepts a **120-second** span (±60 s), so when a sender's
  > clock runs Δ ahead, the dedup entry expires Δ seconds *before* the frame
  > stops being acceptable. The relay needs no key and no clock control — it
  > captures a frame, waits, and re-sends. Demonstrated: with the sender 45 s
  > ahead, the same secret was written to the clipboard **twice**. The defence
  > failed on precisely the condition it exists to tolerate.
- **When the cache is full, reject new traffic. Never evict a still-valid
  entry.** Eviction under pressure is exactly how an attacker would reopen the
  replay window.
- **Fail closed** on missing or corrupt cache state, and on detected clock
  rollback. A receiver that cannot prove an event is new must refuse it.

  **Recovery is part of the requirement.** v1.0 specified the trip and not the
  reset, which is a permanent self-inflicted denial of service: an unauthenticated
  NTP step on the tailnet trips it, and the device still refuses legitimate
  traffic a day later. A tripped receiver must expose an explicit operator
  action — "resume after clock correction" — that clears the tripped state and
  **flushes the dedup cache**, since entries dated under the bad clock cannot be
  trusted. It must not clear itself on a timer. (T2/F9.)

  Note the forward-step case too: an NTP jump forward expires every entry at
  once, because expiries are absolute. That reopens the replay window without
  tripping anything, which is why retention uses `max(now, timestamp_ms)` above
  rather than a wall-clock deadline alone.

- **Dedup cache capacity: at least 4,096 entries**, and it is a fixed
  preallocated bound, not a growth target. At the traffic this system carries,
  4,096 entries covers the 120-second acceptance window many times over. A relay
  cannot force eviction: step 7 runs only on *authenticated* frames and the relay
  holds no key — verified in T2, where 500 replayed frames left the cache at
  size 1. (T2/F13.)
- A retry reuses the original `event_id`, nonce and ciphertext — the identical
  frame — within the 60 s window. Never re-encrypt for a retry; that produces a
  new event ID and defeats dedup.

### What this does not defend against

`sender_id` is **not authentication**. Every enrolled device holds the group key
and can therefore forge any `sender_id`. It exists for dedup and routing only.

This is accepted, not overlooked: all enrolled devices are equally trusted
("if they're enrolled, they're mine"). The mitigation for an untrusted device is
non-enrollment.

**Dedup also cannot stop Universal Clipboard duplication.** When the iPhone sends
directly and Universal Clipboard separately delivers the same text to the Mac,
the Mac's re-send is a different sender with a different event ID carrying the
same content — a legitimately new event by every test in this document. That is
solved in the macOS agent by provenance filtering (S5), not here.

---

## 6. Key and epoch management

- Key: 32 bytes from the OS CSPRNG. Generated **locally on a device**, never on
  the relay, never typed into a page the relay serves.

### CSPRNG failure is fatal — check it

**Every call that draws a nonce or a key MUST check the CSPRNG's return status
and abort on failure. Never discard it.**

`SecRandomCopyBytes` returns an `OSStatus`; the common idiom discards it, which
on failure leaves the buffer **all zeroes**. A repeated nonce under one key
gives an attacker `P1 XOR P2` and recovery of the Poly1305 key for that nonce —
at which point the relay can **forge** frames, not merely replay them. That is
the only failure in this document that converts an untrusted relay into a
trusted one.

Neither reference implementation generates a nonce (both use fixed values so the
vectors stay reproducible), so this operation has no reference code and no
vector. It is the single most dangerous line in each agent and must be reviewed
by hand in T5 and T6. (T2/F8; the warning existed in PLAN.md §3.1 and was lost
when this document was written.)
- `key_epoch` increments on every rekey. Frames from a previous epoch are
  rejected outright — not decrypted and discarded, rejected at step 3.
- **Budget: 2^32 encryptions per epoch — observability, not a gate.** Each
  device counts its own encryptions and surfaces the total. It does **not** stop
  sending, and a missing or reset counter is **not** an error.

  > Revision v1.1 (T2/F7). v1.0 made this a persisted, enforced per-device quota
  > — while §1 simultaneously called persisted counters "exactly the fragility
  > to avoid". Both could not be true. Since nonces are random rather than
  > counter-derived, a rewound counter causes budget *overrun*, not nonce
  > *reuse*: the system is safer than its own argument, and the enforcement
  > machinery bought nothing while adding a way to fail. The real invariant is
  > "new epoch ⟺ new key" (below), which is what actually bounds encryptions per
  > key. Fail open here; fail closed on replay.
- Storage: Keychain on iOS and macOS; DPAPI on Windows.

### Rekey procedure

> ⚠️ **Never transport the new key over BatonPass itself.** Copying the new key
> on the Mac and Back-Tapping it to Windows encrypts it **under the old key at
> the old epoch** and fans it out to every current subscriber — including the
> device you are revoking. Revocation would not merely fail; it would hand the
> revoked device its own replacement.
>
> This is the most important sentence in the document. v1.0 forbade exactly one
> transport — a relay-served page — and said nothing about the one the user
> actually has to hand. (T2/F4.)
>
> Move key material out of band: read it off one screen and type it into the
> other, or use a QR code, or a password manager that is not this product.

1. **Pause sending on every device.**
2. **Remove the revoked device from the relay allowlist** (its `StableID`), so it
   stops receiving ciphertext immediately, before any new material exists.
3. Generate a new key locally on one retained device.
4. Import it **out of band** into each retained device — see the warning above.
   On iOS this is native local import into the Keychain; a CLI is not an
   implementation for the iPhone.
5. Increment `key_epoch`.
6. **Destroy the epoch-N key material on every retained device.** A retained
   device that still holds key N can decrypt anything the revoked device
   captured or replays, and a later restore-from-backup can resurrect it
   (see F5 below).
7. Resume.

**Revocation requires steps 2, 4 and 6 together.** None of them is sufficient
alone:

- Epoch bump alone: the revoked device still holds key N and still receives
  ciphertext, so it decrypts everything sent before anyone finishes rekeying.
- Allowlist removal alone: **the relay never holds the key and cannot decrypt**,
  so removing a peer stops delivery but does not stop that peer decrypting
  anything it already captured.
- Out-of-band transport alone: without allowlist removal the revoked device is
  still a subscriber.

### Invariant: a new epoch always means a new key

`key_epoch` is not a version counter and must never be incremented on its own.
Bumping the epoch while keeping the key gives 2^33 encryptions under one key and
silently doubles the nonce-collision exposure the budget exists to bound.

**Exactly one epoch is live at a time.** Frames from any other epoch are
rejected outright (§4 step 3). Do not add a rollover grace period: the moment
two epochs are simultaneously acceptable, step 3 — which runs on an
*unauthenticated* header field — becomes attacker-controlled key selection.
(T2/F10.)

### Backup and restore

Key material and dedup state must be stored **non-backed-up and device-local**:
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` on iOS and macOS, and DPAPI with
machine scope on Windows.

A restore-from-backup produces state that is **stale but internally
consistent** — the clock is correct, the dedup cache parses, nothing is corrupt.
None of the fail-closed conditions in §5 fire, so the relay can replay the
restored window; and a device restored to a pre-rekey snapshot comes back at
epoch N holding key N, handing a revoked device a live channel again.

Receivers must additionally keep a **monotonic acceptance counter** alongside
the dedup cache and refuse to run if it ever moves backwards. (T2/F5.)

---

## 7. Test vectors

`vectors.json` holds frames with known keys, nonces and event IDs, each with its
expected plaintext and full frame bytes in hex.

Generated by `ref-swift`, independently verified by `ref-csharp`. Both must pass
before T5 or T6 begins. The negative vectors must all be **rejected** — an
implementation that accepts a tampered frame passes no part of this spec.

Vector classes:

| class | asserts |
|---|---|
| `basic` | ASCII round-trip |
| `unicode` | astral emoji, kana, combining marks survive byte-exactly |
| `empty` | zero-length plaintext is valid |
| `max_size` | 65,536-byte plaintext is accepted |
| `tampered_header` | flipped header bit is rejected (AAD binding works) |
| `tampered_ciphertext` | flipped ciphertext bit is rejected |
| `tampered_tag` | flipped tag bit is rejected |
| `truncated` | short frame is rejected before decryption |
| `bad_version` | `version != 1` is rejected |
| `epoch_max` / `epoch_zero` | big-endian uint32 epoch encoding |
| `sender_max` / `sender_zero` | big-endian uint32 sender encoding |
| `timestamp_max` / `timestamp_zero` | big-endian uint64 timestamp encoding |
| `event_id_all_ff` | `event_id` is opaque bytes, not an integer |
| `nonce_all_zero` | a zero nonce is structurally valid — see the CSPRNG note in §6 |
| `len_49_old_min` / `len_53` / `len_60` | the 49–60 hole from v1.0 is rejected |
| `len_0` / `len_1` | degenerate short frames |
| `oversize` | 65,598 bytes is rejected |

> Revision v1.1 (T2/F6). v1.0 claimed `tampered_header` was "the only thing
> proving the AAD is bound, and a broken AAD implementation passes every other
> vector". **That is false.** Five deliberately broken AAD constructions — AAD
> omitted, version only, header minus version, header plus nonce, and the whole
> frame — were each run against the *positive* vector `basic` and all five were
> rejected. The AAD is a tag input, so every positive vector already pins it,
> and the C# re-seal pins the sending side too.
>
> The real gap was different and worse: v1.0's twelve vectors shared **one
> header body**. Epoch, `sender_id` and timestamp were never varied, so a
> receiver could encode any of them wrongly and still pass the entire suite.
> v1.1 adds eight header-variation vectors (8 distinct positive headers) and six
> length-boundary negatives around the corrected 61-byte minimum.

### What the vectors do NOT cover

**The vector suite exercises §4 step 4 and nothing else.** It cannot test steps
3, 5, 6 or 7 — epoch rejection, the freshness window, dedup, and persist-before-
write — because those depend on receiver state and wall-clock time, which a
static file cannot express.

Every bug T2 found in the normative text lived in exactly those steps and passed
the whole suite. So **"vectors.json is the contract" is only true of the frame
format.** T4, T6 and T8 each need their own stateful tests for the steps above,
and those tests are not optional just because the vectors are green. This matters
most where implementation is delegated to a bounded worker, who will reasonably
read a passing suite as done.
