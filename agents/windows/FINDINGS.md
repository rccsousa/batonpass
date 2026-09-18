# T6 — Windows session agent

**Status: implemented and verified against the live relay.** 52 tests passing.
Written up here from the implementing agent's report; it was blocked from
writing files itself.

## Tests

```
Passed! - Failed: 0, Passed: 52, Skipped: 0, Total: 52
```

- **26/26 conformance vectors**, loaded from `crypto/vectors.json` at its real
  repo path rather than a copy, so the agent cannot drift from the spec silently.
  Same scope as the C# reference: length and version, decrypt and tag, byte-exact
  re-seal.
- **14 receiver state machine tests**, covering the steps the vectors explicitly
  cannot reach. Every bug the T2 review demonstrated has a regression here:
  - exact replay rejected
  - clock-ahead sender at 1 ms, 59,999 ms and 60,000 ms accepted (T2/F3 boundary)
  - a `UInt64.MaxValue` timestamp rejected by an unsigned guard *before* any
    signed arithmetic runs — the underflow that trapped Swift
  - **T2/F1 directly**: sender 45 s ahead accepted, replay at now+70 s still
    rejected. That is past the old buggy 60-s-from-acceptance expiry and inside
    the corrected `max(now, timestamp) + 60s` retention
  - cache full at capacity 4096 rejects the 4097th sender, and the *original*
    first frame is still rejected as a duplicate — proving nothing was evicted
  - persist-before-write enforced structurally: persistence runs inside
    `TryAccept`, before plaintext can reach any caller
  - fail closed on corrupt persistence, on counter-anchor/dedup-file
    disagreement (T2/F5), and on live clock rollback
  - resume-after-clock-correction never self-clears; only an explicit call does
- Plus dedup cache (4), Phoenix wire codec (3, checked against the relay's actual
  serializer source), secure random (2).

## Verified live on `windows-pc`

- **Session-0 refusal.** Running over SSH exits 1 with the correct message and
  never attempts a clipboard call. This is asserted as correct behaviour, not
  worked around.
- **Key import.** DPAPI-protected key and config written under
  `C:\ProgramData\BatonPass` without elevation.
- **Real relay round trip, twice.** Two processes exchanged a frame over
  `ws://100.64.0.10:4000/socket/websocket?vsn=2.0.0`, topic `clipboard:home`,
  using `windows-pc`'s real `StableID`. Then the full agent loop received a frame from
  a separate sender and ran the entire pipeline — join, decode, decrypt and verify
  tag, epoch and freshness and dedup, persist, then `WriteText` including all
  three Win+V exclusion formats in the same `OpenClipboard` session — with a
  matching readback and no error.

## Not tested

- Whether the Win+V exclusion formats actually suppress retention in the visible
  Clipboard History UI. The calls succeed; confirming the effect needs session 1.
- **Cross-process clipboard visibility in session 0 is unreliable**, observed
  directly: a separate probe process could not see what the agent had just
  written. This independently reproduces S3's finding that a session-0 clipboard
  is window-station-local and invisible.
- Local-copy → send direction on real hardware. It shares fully tested code with
  the verified receive path, but no external process reliably landed in the same
  window station to trigger a detected change.
- Locked workstation and true session-1 desktop behaviour.
- Live replay of an identical previously-accepted frame over the socket; covered
  by unit tests only.
- DPAPI across a reboot, as opposed to across process restarts.

## Findings against other components

**The relay did not implement `GET /health`** despite CONTRACT.md §6 promising
it — found by hitting it from `windows-pc` and getting `Phoenix.Router.NoRouteError`.
Now implemented, allowlist-gated like the socket, with tests.

**DPAPI machine scope is weaker than the iOS equivalent, and the spec should say
so.** SPEC.md §6 prescribes it for Windows, but it only controls *which key*
decrypts the dedup-state blob. Unlike iOS's `ThisDeviceOnly`, it does not exclude
the file from backup software. The implemented defence is an independent counter
anchor stored under `%LOCALAPPDATA%`, deliberately apart from the dedup state
under `%ProgramData%`, so restoring one directory from an old snapshot is caught.
A whole-machine snapshot revert rolling both stores back atomically is **not**
caught, and would need a TPM. Out of scope, recorded rather than hidden.

No bugs found in the envelope spec or the relay contract themselves.
