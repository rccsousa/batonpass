# BatonPass — Task Plan

Execution breakdown of `PLAN.md` v2. Ordered, with owners, dependencies and
acceptance criteria. Nothing here is started.

**Milestone 1 (the only one that matters first):** copy in Google Authenticator
on iPhone → one Back Tap → paste on Windows.

Legend — **Owner**: which model/agent does the work.
`Opus` = deeper reasoning, `Spark` = `gpt-5.3-codex-spark` bounded worker,
`Sonnet` = standard implementation. Spark tasks are marked **only** where a
frozen contract already exists for them to build against.

---

## Stage 0 — Spikes (all concurrent, none depend on each other)

Nothing in Stage 1 starts until S1, S3, S4, S5 report. S2 can trail S1 slightly.

### S1 — iOS App Intent receives clipboard text as a parameter ⚠️ SCAFFOLD BUILT, UNTESTED ON DEVICE
**Owner:** Opus (`general-purpose`) · **Blocks:** everything iOS

Build a throwaway iOS app exposing an `AppIntent` with a `String` parameter, and
a Shortcut that does `Get Clipboard` → pass to intent. The app must never touch
`UIPasteboard`.

**Must test on a real device, not a warm simulator:**
- [ ] Cold start (app never launched since boot)
- [ ] App force-terminated
- [ ] Concurrent invocations (double Back Tap twice quickly)
- [ ] First-run permission prompts — what actually appears, and when
- [ ] Locked **and** unlocked device states
- [ ] Keychain accessibility class under each lock state
- [ ] Tailscale reconnection mid-send
- [ ] User cancellation
- [ ] Network timeout
- [ ] Text passed **as a String** — verify a TOTP code with a leading zero
      (`012345`) survives intact and is not coerced to a number
- [ ] The intent **awaits** the network call; no detached work returning early
      success

**Acceptance:** intent reliably receives text and completes a network POST from a
cold start on a locked-then-unlocked device, with no "Allow Paste" alert.

**If it fails, take the ladder in order — do not improvise:**
1. Networking-in-intent fails → intent encrypts, returns ciphertext, Shortcut
   POSTs it.
2. Background execution fails → foreground app + `UIPasteControl` → encrypt →
   send.
3. **Never** plaintext relay traffic. **Never** clipboard text in a launch URL.

### S2 — Back Tap gesture reliability
**Owner:** Opus (`general-purpose`) · **Depends:** S1 scaffold

- [ ] Measure end-to-end latency, Back Tap → POST sent
- [ ] Reliability over ~30 real invocations across a normal day
- [ ] Confirm the honest claim: *one gesture, after setup, while unlocked, no app
      switch* — and record where that breaks

**Acceptance:** a number for latency and a failure rate, not a vibe.

### S3 — Windows clipboard access ✅ RESOLVED
**Owner:** Spark implements the probe · Opus decides the adapter contract

Settles the council's one live deadlock (Fable: PowerShell-stdin + explicit
UTF-8; Astra: native Win32, don't shell out at all).

- [ ] Native Win32 clipboard read/write probe
- [ ] Clipboard **contention** — another app holding the clipboard open
- [ ] Unicode: emoji, CJK, combining marks, CRLF vs LF
- [ ] Win32 clipboard **sequence number** for change detection
- [ ] Process lifecycle in an interactive logon session
- [ ] Confirm Win+V Clipboard History behaviour and how to exclude items

**Acceptance:** a written adapter contract (read, write, change-detect) and a
recommendation with evidence. Native Win32 is preferred unless the probe shows a
concrete reason otherwise.

### S4 — `tailscale whois` peer identity in Phoenix ✅ PASSES
**Owner:** Opus, direct (one-file Plug; faster than delegating)

- [ ] Map an inbound connection's source IP to tailnet node + user
- [ ] Behaviour when the peer is not in the tailnet
- [ ] Behaviour when `tailscaled` is down — must **fail closed**
- [ ] Confirm binding to the tailnet interface only, not `0.0.0.0`

**Acceptance:** a Plug that rejects any peer not on an explicit allowlist, with a
test proving it fails closed.

### S5 — Universal Clipboard × BatonPass loop safety ✅ RESOLVED
**Owner:** Opus (`general-purpose`)

Universal Clipboard is a second propagation path. A macOS agent watching the
pasteboard will see UC-delivered iPhone items.

- [ ] Does a UC-delivered item look distinguishable from a local copy?
      (`NSPasteboard` types, source metadata, `changeCount` behaviour)
- [ ] Does iPhone → (UC) → Mac → (BatonPass) → Windows duplicate the Windows
      delivery when the iPhone also sent directly?
- [ ] Can a BatonPass-written item on the Mac echo back out?

**Acceptance:** either a reliable mechanism to ignore UC-originated items, or a
documented statement that the Mac agent must be off while the iPhone sends
directly.

---

## Stage 1 — Milestone 1: iPhone → Windows

### T1 — Crypto envelope specification ✅ DONE
**Owner:** Opus, **not delegated** · **Blocks:** T2, T4, T5

Delivered: `crypto/SPEC.md`, `crypto/vectors.json` (12 vectors), Swift generator and
C# verifier. 12/12 passing, including byte-exact cross-language re-seal.
**Deviation from PLAN §3.1:** IETF ChaCha20-Poly1305, not XChaCha20 — rationale
and safety margin in SPEC.md §1.

- [ ] XChaCha20-Poly1305, random 192-bit nonces from OS CSPRNG via libsodium
- [ ] Wire format frozen and written down: version, key epoch, event ID, sender
      ID, timestamp, ciphertext
- [ ] All of the above in the **AAD**, with a byte-exact canonical encoding
      (cross-language: Swift and C# must agree)
- [ ] Bounded parse limits defined before any allocation or decryption
- [ ] Key-use budget: ceiling per epoch, divided into persisted per-device quotas
- [ ] Rekey procedure written as steps a human can follow
- [x] **Test vectors** committed, so Swift and C# can be verified against the
      same fixtures — 26 vectors, 26 passing
- [ ] **Stateful tests are NOT covered by vectors.** The suite exercises §4
      step 4 only. Steps 3, 5, 6 and 7 — epoch rejection, freshness window,
      dedup, persist-before-write — need their own tests in T4/T6/T8. Do not
      read a green vector run as coverage of those.

**Acceptance:** a spec document plus fixtures. No code needed to review it.

### T2 — Adversarial pass on the envelope ✅ DONE
**Owner:** `miguel-regala` @ Opus · **Depends:** T1

Findings in `crypto/T2-FINDINGS.md`, PoCs in `crypto/t2-attack/`. Fifteen
findings; four demonstrated with working attacks. SPEC.md revised to v1.1 and
the vector suite grown 12 → 26 (26/26 passing).

**Every demonstrated bug passed the original 12-vector suite**, which is the
finding that matters for delegation: a green run did not mean correct.

Attack the spec before anything is built: nonce reuse, replay across epochs,
AAD encoding ambiguity between languages, downgrade, truncation, sender-ID
forgery by a keyholder, clock rollback.

**Acceptance:** written findings; T1 revised; explicitly note that sender-ID
forgery by a keyholder is **accepted**, not fixed (all enrolled devices are
equally trusted).

### T3 — Relay contract ✅ DONE
**Owner:** Opus · **Depends:** S4

Delivered: `relay/CONTRACT.md`.

- [ ] Channel/topic shape, join and authentication flow
- [ ] Message size limits, rate limits, backpressure policy
- [ ] Explicitly: no key, no database, no persistence, no shell, no crypto
- [ ] Logging policy — metadata only, **never** content, including error paths

**Acceptance:** a frozen contract Spark can build fan-out against.

### T4 — Elixir relay implementation ✅ DONE
**Owner:** Opus · **Depends:** T3, S4

Delivered: `relay/app`. 19 tests, 0 failures. Kept in-house rather than delegated:
the contract's guarantees are mostly *absences* (no key, no store, no shell, no
echo), and absences are what a bounded worker is least likely to preserve.

- [ ] Phoenix app, WebSocket channels, opaque blob fan-out
- [ ] `tailscale whois` allowlist Plug from S4
- [ ] Bound to the tailnet interface only
- [ ] Size and rate limits from T3
- [ ] Pause and per-peer receive toggles — **functional, config/CLI only**

**Acceptance:** two fake clients exchange blobs; relay refuses a non-allowlisted
peer; relay has no code path that can decrypt.

### T5 — iOS sender app ⚠️ BUILDS, NOT YET INSTALLED
**Owner:** Opus · **Depends:** S1, S2, T1

Delivered: `agents/ios`. Builds for simulator and device against the real SDK.
App Intents metadata confirms `openAppWhenRun: false`, and `nm -u` on the device
binary shows **zero** paste-related imported symbols — the app structurally
cannot raise an "Allow Paste" alert.

Shares `core/` with the macOS agent, so the envelope exists once in Swift.

**Blocked on hardware, not code:** an Apple ID must be added in Xcode → Settings
→ Accounts to get a signing identity (`security find-identity` currently reports
0). Then the S1 on-device matrix runs.

- [ ] `AppIntent` with String parameter (never reads `UIPasteboard`)
- [ ] libsodium XChaCha20-Poly1305, envelope per T1
- [ ] **Key in Keychain, with native local import** — not a CLI
- [ ] Back Tap Shortcut, documented setup steps
- [ ] Awaits the POST; surfaces failure rather than silently succeeding

**Acceptance:** Authenticator code → Back Tap → relay receives a valid envelope.

### T6 — Windows session agent ✅ DONE
**Owner:** Sonnet implements · Opus reviews · **Depends:** S3, T1, T3

Delivered: `agents/windows`. 52 tests passing, verified against the live relay
from `windows-pc` — full pipeline through to a clipboard write. See
`agents/windows/FINDINGS.md`.

- [ ] **Interactive logon-session process**, not a Windows service
- [ ] **Health check: refuse to run when `processSessionId != activeConsoleSessionId`.**
      S3 observed that native clipboard calls *succeed* in session 0 against a
      window-station-local clipboard no user can see — writes return success,
      reads round-trip, nothing errors. Degrading quietly means syncing into a
      void. Fail loudly instead.
- [ ] **Native Win32 clipboard, not PowerShell.** Settled by S3 on evidence:
      native 6/6 byte-exact, PowerShell 3/6 and failing *silently*
      (`exitCode 0`, `status true` while corrupting emoji, CJK and combining
      marks). Not a preference — the PowerShell path is wrong.
- [ ] **Set all three Win+V exclusion formats on every write**, inside the same
      `OpenClipboard`/`EmptyClipboard` session as the payload:
      `ExcludeClipboardContentFromMonitorProcessing`,
      `CanIncludeInClipboardHistory` = DWORD 0,
      `CanUploadToCloudClipboard` = DWORD 0.
      `windows-pc` has `EnableClipboardHistory: 1`, so without this every TOTP code
      and API key is retained in Win+V. Verify the suppression actually works —
      S3 confirmed the API exists but did not observe it taking effect.
- [ ] `OpenClipboard` retry: exponential backoff, base 100 ms, ~8 attempts.
      Classify busy/locked as retryable. (S3: clears real contention.)
- [ ] Receiver replay defence per T1/§3.4:
      authenticate first → dedup `(epoch, sender-ID, event-ID)` →
      **persist acceptance metadata before writing the clipboard** →
      retain IDs for the full acceptance window → **reject when full, never
      evict a still-valid ID** → **fail closed** on corrupt state or clock
      rollback
- [ ] Loop suppression: last-written content hash + Win32 sequence number.
      **Treat any strictly increasing sequence number as a change — never
      `previous + 1`.** S3 observed a consistent delta of **5** per write across
      both sessions.
- [ ] Never re-forwards a received event
- [ ] Clipboard writes serialized through one worker
- [ ] Setup doc notes Win+V history retains secrets independently

**Acceptance:** receives an iPhone envelope and writes the clipboard; replays are
rejected; a mid-write crash cannot produce duplicate delivery.

### T7 — Milestone 1 gate
**Owner:** `adversarial-reviewer` @ Opus, then `/security-review`

- [ ] End-to-end: Authenticator → Back Tap → paste on Windows
- [ ] Replay injection rejected
- [ ] Relay restart mid-flight handled
- [ ] Key material absent from logs, crash dumps and the repo

---

## Stage 2 — macOS agent (does not block Milestone 1)

### T8 — macOS session agent ✅ DONE
**Owner:** Opus · **Depends:** T1, T3, S5

Delivered: `agents/macos`. 15 receiver tests + 26 vectors passing, and verified
end to end over the tailnet: sealed on one agent, through the relay, written to
the clipboard byte-exact including emoji, kana and a leading-zero TOTP.

- [ ] **LaunchAgent**, not LaunchDaemon
- [ ] `NSPasteboard.changeCount` polling for change detection
- [ ] Same receiver replay defence as T6
- [ ] **Mandatory first line of the change handler:**
      `if item.types.contains("com.apple.is-remote-clipboard") { return }` —
      before hashing, before reading payload data. S5 observed this marker on
      3/3 Universal Clipboard deliveries and 0/6 local copies. It is a
      **zero-byte type**: test `types.contains`, never the value, which is `""`
      and fails open.
- [ ] Write with `prepareForNewContents(with: [.currentHostOnly])` on **every**
      write. Belt, not braces — S5 saw it **leak once in five trials**, so it
      must not be the only defence.
- [ ] **Self-check for marker loss:** if the agent never observes
      `com.apple.is-remote-clipboard` over its lifetime while UC peers exist,
      surface it in status output. The marker appears **zero times in the macOS
      SDK** — it is undocumented and fails *open* if a future release drops it.

**Acceptance:** Mac ↔ Windows both directions, with no loop when Universal
Clipboard is also active.

---

## Stage 3 — Phase 2 surface

### T9 — Test harness
**Owner:** Spark builds · Opus defines the adversarial cases and expected results

- [ ] Fake relay
- [ ] Disconnect and replay injection
- [ ] Restart runners
- [ ] Cross-language fixture runner against T1's test vectors

**Note:** Spark's tests must never define what "secure" means — the expected
results come from T1/T2.

### T10 — LiveView enrollment UI
**Owner:** `subvisual-designer` @ Opus · **Depends:** T4

- [ ] Approve/revoke devices; surface the T4 toggles; global pause
- [ ] **Key material never passes through a relay-served page** — the lab machine
      can replace that page's JavaScript

### T11 — iOS receive + fetch-on-activity
**Owner:** Opus · **Depends:** T5

- [ ] Foreground fetch that writes the pasteboard (background write is
      impossible; `UIPasteControl` pastes *into* an app and is not a receive
      control)
- [ ] Pending-item store with a defined expiry and reconnect policy
- [ ] Fetch on unlock/foreground/non-idle

---

## Stage 4 — Hardening (debt, recorded)

### T12 — Pinned mutual TLS agent-to-agent
**Owner:** Opus · Fingerprints compared out of band. The council judged this the
better endpoint; it lost Stage 1 to time-to-MVP.

### T13 — Android client

Foreground-only MVP in `agents/android`; uses the existing online-only relay,
not the deferred T11 fetch path.

- [x] Native enrollment and Android Keystore-protected device-local state
- [x] Explicit clipboard/text send and `ACTION_SEND` share target
- [x] Receive to clipboard while the activity is focused
- [x] Existing envelope vectors, Phoenix framing, replay persistence, clock recovery
- [x] Gradle build, JVM tests, Android instrumentation suite, setup documentation
- [x] Real Mac clipboard → Phoenix relay → Android emulator clipboard → paste (2026-09-18)
- [ ] Physical-device Tailscale enrollment and desktop interoperability smoke test
- [ ] Background receiving (outside the foreground MVP)

---

## Critical path

```
S1 ─┬─> T5 ─┐
S2 ─┘       │
T1 ─> T2 ───┼─> T7  (Milestone 1)
S4 ─> T3 ─> T4
S3 ─────────> T6 ──┘
S5 ─────────> T8   (parallel, not blocking)
```

**The two tasks that can invalidate the design are S1 and S5.** Run them first.

## Not doing

Clipboard history · offline catch-up · file transfer (Taildrop) · app-state
continuity · multi-user · any agent on the headless Debian · enrolling the lab
server or any colleague machine.
