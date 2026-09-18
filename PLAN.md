# BatonPass — Implementation Plan (v2)

Consolidated from model council run `20260911-103723-57a7fcb3` (moderator Claude
Opus; members Claude Fable, GPT-6 Astra), then revised twice:

- **v1** after tool-based verification the council could not do (it had no tools).
- **v2** after a follow-up audit by Astra on the revised plan, plus local
  verification of the two API claims it raised. Both were correct; see §8.

Status: nothing built.

---

## 1. Findings that reshape the council's plan

### 1.1 You already own half of what you asked for

Universal Clipboard already gives you copy-on-Mac → paste-on-iPhone and the
reverse, no extra action, today. It is built on the same protocol as Handoff: BLE
advertisement discovery, mDNS-over-AWDL service discovery, an authentication
phase deriving a session key, then payload transfer. Trust root is the Apple
Account and device pairing — not the network.

**BatonPass's real job is not "rebuild Handoff". It is "join Windows and the
headless Debian to a continuity set that already works for the Apple devices."**

⚠️ This does **not** mean the Apple pair is free of consequences. Universal
Clipboard is a **second propagation path** running alongside BatonPass. A
BatonPass macOS agent watching the pasteboard will see items that Universal
Clipboard delivered from the iPhone, and may re-send them as apparently local
copies — duplicating sends or creating an echo. "Untouched" is not "loop-safe".
Spike **S5** exists for this.

### 1.2 Your essential scenario cannot be zero-gesture on iOS

iOS restricts pasteboard reads to the **foreground**, and has since iOS 9,
specifically to prevent background clipboard monitoring. No entitlement, no
background mode, no workaround. An iOS app cannot notice a copy while
backgrounded.

Since iOS 16, a programmatic pasteboard read also raises an "Allow Paste" alert
unless it comes via the system Paste menu, hardware Cmd-V, or `UIPasteControl`
(where the tap is the consent).

**Accepted gesture:** Back Tap → Shortcut → send. Stated precisely, and *not* as
"one tap, no launch, no prompt" — that was an over-claim in v1. The honest target
is:

> **one gesture, after setup, while unlocked, with no app switch.**

Back Tap is a double- or triple-tap. Shortcuts may request data permissions on
first run. Execution depends on device state.

### 1.3 Consequence: build order

iOS originates your essential scenario and is your most-used device. The council
sequenced macOS+Windows first on the assumption iOS was secondary. Reordered.

**First acceptance milestone is iPhone → Windows. macOS does not block it.**

---

## 2. Architecture

```
  iPhone (iOS)                 Mac (macOS)            Windows PC
  Back Tap → Shortcut          session agent          session agent
  → App Intent → app           (LaunchAgent)          (logon task, interactive)
        │                          │                      │
        └──── ciphertext ──────────┼───── ciphertext ─────┘
                                   │
                         headless Debian
                         Phoenix relay ← relay-only, NEVER enrolled
                         opaque blobs · no key · no DB · no shell
                         tailnet iface only · `tailscale whois` allowlist
```

**Settled:**

- The relay **relays opaque ciphertext**. No group key, no database, no content,
  no history. Your exclusion of the lab machine is preserved structurally, not by
  policy.
- **The server never invokes a shell.** It has no clipboard to write.
- **Agents are session-scoped, not services or daemons.** A Windows *service* and
  a macOS *LaunchDaemon* run outside the user session and cannot reliably reach
  the clipboard. Windows: interactive user process started at logon. macOS:
  **LaunchAgent**, not LaunchDaemon. (v1 said "service"/"daemon" — wrong.)
- Where any component must spawn a helper, it spawns a **fixed absolute
  executable with an argv list, payload on stdin — never argv, never a shell
  string.**
  ⚠️ **`System.cmd/3` cannot do this.** It has no stdin option; `:input` is
  rejected outright (verified locally, §8). The Elixir primitive is:
  ```elixir
  port = Port.open({:spawn_executable, "/usr/bin/pbcopy"},
                   [:binary, :exit_status, args: []])
  Port.command(port, payload)
  ```
  In practice the relay spawns nothing and the agents are native per-platform, so
  this mostly matters if you write the macOS agent in Elixir.
- **Tailscale SSH is dropped as transport.** Once every device runs a session
  agent, SSH adds no clipboard capability and one more inbound execution
  interface. Keep it as your admin tool; WireGuard, node identity and ACLs are
  yours regardless.
- **"Contained to our tailnet" is not a containment claim.** Network position is
  not identity. Enrollment is the gate.
- **No clipboard history, no offline catch-up, no content logging.**
  ⚠️ Caveat: no-history code cannot guarantee absence from **OS** clipboard
  history. Windows Clipboard History (Win+V) and third-party managers will retain
  pasted secrets independently. Recommend disabling Win+V history on the Windows
  endpoint; note it in setup either way.

**Trust model:** one group key shared by enrolled devices. All enrolled devices
equally trusted with all content — your position ("if they're enrolled, they're
mine"). Least-trusted-device mitigation is **non-enrollment**.

⚠️ **Any keyholder can forge sender IDs.** Sender ID is routing and dedup
metadata, not authentication between keyholders. Per-peer receive toggles and
relay-hosted enrollment controls are convenience and mistake-avoidance — **never**
security boundaries against a device that holds the key, and relay-side controls
can never become endpoint authority.

---

## 3. Security requirements (Phase 1 gates)

1. **AEAD: XChaCha20-Poly1305, random 192-bit nonces** from the OS CSPRNG via
   libsodium, fresh for every encryption. Never seed from time; never reset an
   application PRNG per invocation (cold-started iOS clients make this a live
   risk, not a theoretical one).
   ⚠️ **OTP's `:crypto` does not provide XChaCha20** — it offers `chacha20` and
   `chacha20_poly1305` (IETF, 96-bit nonce) only; verified locally (§8). Use a
   libsodium binding, per platform: Swift/CryptoKit+libsodium (iOS/macOS),
   libsodium binding for C#/.NET (Windows).
   **The relay needs no AEAD at all** — it never decrypts. This removes the
   Elixir crypto question entirely.
2. **Authenticate the envelope, not just the payload.** Version, key epoch, event
   ID, sender ID and timestamp all in the AAD.
3. **Bounded parsing before expensive work.** Reject oversized/malformed frames
   before allocation or decryption.
   ⚠️ **Envelope dedup does not stop Universal Clipboard duplication.** S5
   confirmed that iPhone → relay → Windows *and* iPhone → UC → Mac → relay →
   Windows both deliver. The Mac's re-send is a different sender with a
   different event ID carrying the same content — a legitimately new event by
   every envelope-level test. Provenance filtering in the macOS agent (§T8) is
   the only correct fix; content-hash dedup would also swallow a deliberate
   re-copy.
4. **Receiver replay defence** (every receiver; a sender-only iOS client needs
   none):
   - Authenticate **first**, then deduplicate on `(epoch, sender-ID, event-ID)`.
   - **Persist acceptance metadata *before* writing the clipboard.** A crash may
     lose a delivery; it must never enable a duplicate one.
   - Retain IDs for their full remaining acceptance window, including allowed
     clock skew. **Reject new traffic when the cache is full — never evict a
     still-valid ID.**
   - **Fail closed** on missing or corrupt state, or on unsafe clock rollback.
   - v1 said "persisted or explicitly reset-on-restart with the consequence
     documented". That is **not** sufficient. Documenting a reset does not make
     replay safe. Corrected.
   - Retries reuse the original event ID and the original envelope, within a
     short deadline.
5. **Enforceable key-use budget.** Conservative ceiling (e.g. 2^32 encryptions
   per epoch) divided into **persisted per-device quotas**.
6. **Rekey, working day one:** pause → generate fresh key locally → import
   independently into each retained device → reject the old epoch → resume.
   Relay revocation alone cannot revoke a shared key.
   ⚠️ iOS needs **native local import and Keychain storage**. "CLI on every
   device" is not an implementation for the iPhone.
7. **The group key is never typed into a page the relay serves** — that host can
   replace the page's JavaScript.
8. **Pause and per-peer receive toggles ship in Phase 1** as *function*. Their UI
   can wait; their behaviour cannot.
9. Bounded text size, reject rather than fragment. Received events are never
   re-forwarded. Loop suppression via last-written content hash plus
   `NSPasteboard.changeCount` (macOS) and the Win32 clipboard sequence number.
   Clipboard writes serialized through one worker per agent.

---

## 4. Phases

### Phase 0 — Spikes (concurrent; S1 is the risk)

| # | Spike | Question | Blocking |
|---|-------|----------|----------|
| S1 | iOS App Intent receiving clipboard text **as a parameter** from the Shortcut | Can the app do AEAD + POST without ever reading the pasteboard? | Phase 1 |
| S2 | Back Tap → Shortcut → App Intent, on the real device | Latency, reliability, and whether it is genuinely one gesture | Phase 1 |
| S3 | Windows clipboard: native Win32 vs PowerShell-stdin | Settles the council's one live deadlock | Phase 1 |
| S4 | `tailscale whois` on a Phoenix connection | Confirms peer identity mapping | Phase 1 |
| S5 | **Universal Clipboard × BatonPass loop safety** | Does the macOS agent re-send UC-delivered items? Duplicates? Echoes? | Phase 1 |

**S1/S2 must exercise the real Google Authenticator flow**, not a warm simulator:
cold start, terminated app, concurrent invocations, first-run permissions,
locked *and* unlocked states, Keychain accessibility, Tailscale reconnection,
cancellation, and network timeout. Keep the text **as a string** — leading zeroes
matter in TOTP codes. **Await the POST**; do not launch detached work and return
success.

**S1 fallback ladder** (v1's "rethink, don't patch" was too blunt):
1. If networking inside the intent fails → **intent encrypts and returns
   ciphertext; the Shortcut POSTs it.**
2. If background execution itself fails → **foreground BatonPass app +
   `UIPasteControl` → encrypt → send.** More interaction, same confidentiality.
3. **Never** fall back to plaintext relay traffic, and **never** put clipboard
   text in a launch URL.

**S3 note:** correct fixed-script PowerShell with stdin is not automatically
injectable — the council's deadlock was narrower than it sounded. Native Win32 is
still preferred; S3 should validate clipboard contention, Unicode handling, and
process lifecycle.

### Phase 1 — iPhone → Windows, end to end

- **Elixir relay** on headless Debian: Phoenix, WebSocket channels, opaque blob
  fan-out, `tailscale whois` allowlist, tailnet interface only, no database, no
  persistence, no shell, no crypto.
- **iOS sender**: minimal native app exposing an App Intent, plus the Back Tap
  Shortcut. Send only. Keychain-stored key with native local import.
- **Windows session agent**: receive + write clipboard; detect local copies and
  send.
- **macOS session agent** (LaunchAgent): same, but **does not block the
  milestone**.
- Pause and per-peer receive toggles: functional, CLI/config only.

**Acceptance:** copy in Google Authenticator on iPhone → one Back Tap → paste on
Windows.

**Debian gets no agent.** Headless, no clipboard. Mac→Debian already works
through your terminal over SSH; Debian→Mac is OSC 52 in your terminal emulator.
Enrolling it as a clipboard endpoint would be a mistake.

### Phase 2 — Enrollment UI, iOS receive, fetch-on-activity

- LiveView enrollment UI: approve/revoke devices, expose the Phase 1 toggles,
  global pause. Key material still never passes through the relay.
- **iOS receive.** ⚠️ `UIPasteControl` pastes *into* an app — it is **not** a
  network-receive control; v1 conflated the two. iOS receive means a foreground
  fetch that writes the pasteboard, plus optionally a receive Shortcut. Background
  write remains impossible.
- **Fetch-on-activity** (fetch on unlock/foreground/non-idle rather than holding
  eagerly pushed content) requires a **defined pending-item store, expiry policy,
  and reconnect policy** before it means anything. It reduces the window where an
  unlocked Windows box holds the day's keys — it **cannot** undo disclosure that
  already happened.

### Phase 3 — Hardening

- Pinned mutual TLS agent-to-agent, fingerprints compared out of band. The
  council judged this the better endpoint; it lost Phase 1 to time-to-MVP, which
  you named as your priority. Recorded as debt.
- Android client (testing only, same code path as iOS receive).

### Explicit non-goals

Clipboard history. Offline catch-up. File transfer (use Taildrop). App-state
continuity (`NSUserActivity`-style resumption is a different, smaller feature).
Multi-user. Anything on the lab server beyond blind relaying.

---

## 5. Agent and model allocation

Codex Spark (`gpt-5.3-codex-spark`) is available and verified working in this CLI
via `-c model="gpt-5.3-codex-spark"`. It is a small, very low-latency model
(~1000 tok/s on Cerebras) — explicitly speed-over-depth versus full Codex. It is
a *model*, not an agent framework: "Spark agents" are Codex sessions pinned to it.

**Astra's verdict: Spark earns a place here. Start with two workers maximum.**

### Spark may own (bounded implementation, contract already frozen)

| Work | Shape |
|------|-------|
| S3 Windows probe | Implements the native-API probe and the specified tests; a deeper model decides the adapter contract |
| Platform scaffolding | Project shells, build wiring, tray/status UI, adapters — *after* contracts settle |
| Test harness | Fake relay, disconnect/replay injection, restart runners, cross-language fixture runners |
| Relay plumbing | Bounded fan-out — *after* authentication, limits and backpressure are specified |
| Phase 2/3 | Presentation, documentation, CI, Android scaffolding — after platform behaviour is verified |

### Spark must NOT solely own

| Work | Failure mode being guarded against |
|------|-----------------------------------|
| S1/S2 conclusions | Mistaking warm-simulator success for reliable cold-device execution |
| Crypto, replay, rekey | Nonce reuse, crash-window replay, inconsistent AAD encoding, accepting revoked epochs |
| S4 / authentication / enrollment / mTLS | Trusting spoofable headers, relay assertions, or silently replaced identities |
| Loop suppression and fetch semantics | Feedback loops, stale overwrites, implicit retention |
| Final security review | Implementation and tests sharing the same mistaken assumption |

**Collaboration pattern.** One deeper lead supplies frozen interfaces,
invariants, fixtures, file ownership and exact validation commands. Spark returns
small patches plus test evidence. Contract ambiguity escalates immediately; a
second deeper pass reviews integration and attacks the result. Give Spark
scaffolding **and** harness work — but never let its tests define what "secure"
means.

### Deeper allocation

| Work item | Agent | Model |
|-----------|-------|-------|
| S1/S2 iOS spike | `general-purpose` | Opus |
| S5 Universal Clipboard loop spike | `general-purpose` | Opus |
| Crypto envelope (§3) | direct, not delegated | Opus |
| Crypto envelope — adversarial pass | `miguel-regala` | Opus |
| Elixir relay (contract + review) | `general-purpose` | Opus |
| macOS agent | `general-purpose` | Sonnet |
| Windows agent | `general-purpose` | Sonnet |
| iOS app + Shortcut | `general-purpose` | Opus |
| LiveView enrollment UI | `subvisual-designer` | Opus |
| Milestone gate | `adversarial-reviewer` | Opus |
| Pre-ship security pass | `/security-review` | — |

---

## 6. Open questions

1. **S1 outcome.** The entire iOS leg depends on it; fallback ladder in §4.
2. **S5 outcome.** Whether Universal Clipboard and BatonPass can coexist on the
   Mac without echo. If not, the macOS agent may need to ignore UC-originated
   items — mechanism unknown.
3. Windows native Win32 vs PowerShell-stdin — S3 resolves.
4. ~~Is Back Tap acceptable?~~ **Resolved: yes.**

## 7. Uncosted

Windows was promoted to a first-class endpoint late in the council and neither
member costed it. No member would substantiate any effort estimate beyond the
AEAD envelope. Treat all sequencing as ordering, not schedule.

## 8. Verified locally (not taken on an agent's word)

Both claims Astra raised against v1 were checked in this environment and are
correct:

```
$ erl -noshell -eval 'io:format("~p~n",[[C || C <- crypto:supports(ciphers),
    lists:prefix("chacha", atom_to_list(C))]]), halt().'
[chacha20,chacha20_poly1305]          # no XChaCha20

$ elixir -e 'System.cmd("cat", [], input: "hello")'
** invalid option :input with value "hello"    # System.cmd/3 has no stdin
```

Also verified: `codex-cli 0.154.0` accepts
`-c model="gpt-5.3-codex-spark"` and returns normally.
