# S1 — iOS App Intent receives clipboard text as a parameter

**Status: NOT PASSED. NOT FAILED. Scaffold built and compiling; zero on-device
evidence.**

The scaffold exists, builds clean for `arm64-apple-ios` against the real iOS 26.2
device SDK, and is structurally incapable of touching the pasteboard. Everything
the S1 acceptance criterion actually asks about — what happens on a real phone —
is untested, because the phone is not here. `TASKS.md` S1 rules out a simulator
result explicitly, and in any case no simulator runtime is installed on this Mac.

Do not treat anything below as S1 passing. The deliverable is the scaffold plus
the checklist in §5, which Rui runs.

---

## 1. What was built

```
spikes/s1-ios-app-intent/
├── BatonPassSpike.xcodeproj/         hand-written pbxproj, objectVersion 77
├── Info.plist
├── BatonPassSpike/
│   ├── BatonPassSpikeApp.swift       SwiftUI config/log/probe screen
│   ├── SendClipboardIntent.swift     the AppIntent
│   ├── Sender.swift                  awaited URLSession POST
│   ├── Config.swift                  endpoint in UserDefaults
│   ├── SpikeLog.swift                persisted ring buffer
│   ├── KeychainProbe.swift           accessibility-class probe
│   └── AppShortcuts.swift            AppShortcutsProvider
├── receiver/receiver.py              local HTTP receiver, stdlib only
├── SHORTCUT-SETUP.md                 the by-hand setup steps
└── FINDINGS.md
```

The intent:

```swift
static var openAppWhenRun: Bool = false
@available(iOS 26.0, *) static var supportedModes: IntentModes { .background }

@Parameter(title: "Text", inputConnectionBehavior: .connectToPreviousIntentResult)
var text: String

func perform() async throws -> some IntentResult & ReturnsValue<String> {
    let reply = try await Sender.post(text: text, to: endpoint)   // awaited
    return .result(value: "sent \(shape.utf8Length) bytes")
}
```

Failures `throw`. Nothing is dispatched detached, so there is no path that
returns success before the POST resolves. The `URLSession` sets
`waitsForConnectivity = false` on purpose: with it on, a Tailscale drop makes the
request wait rather than fail, and the intent would burn its execution budget
looking healthy.

The receiver prints, per request: raw bytes, the JSON type of `text`, its `repr`,
a UTF-8 hex dump, the codepoints, and whether it starts with `0`. It flags
`text` arriving as anything other than a JSON string. `--delay N` holds the
response N seconds; `--fail 500` always errors.

## 2. Verified here, by command

**The app cannot touch the pasteboard.** Not a promise — checked in source and
in the linked Mach-O:

```
$ rg -ni "pasteboard|uipastecontrol" BatonPassSpike/ Info.plist
ZERO matches
$ nm -u .../BatonPassSpike.app/BatonPassSpike | rg -i paste
ZERO paste symbols in binary
```

`otool -L` shows UIKit linked weakly via SwiftUI only. There is no UIPasteboard
call site, so the iOS 16 "Allow Paste" alert cannot originate in this app. If
that alert appears during the on-device test, it came from Shortcuts, not here —
which is a different and more interesting result.

**It builds, clean, for the device architecture.**

```
$ xcodebuild -project BatonPassSpike.xcodeproj -target BatonPassSpike \
    -sdk iphoneos -configuration Release CODE_SIGNING_ALLOWED=NO ... build
** BUILD SUCCEEDED **        # zero warnings, zero errors
$ swiftc -sdk $(xcrun --sdk iphoneos --show-sdk-path) \
    -target arm64-apple-ios17.0 -O -o BatonPassSpike BatonPassSpike/*.swift
$ file BatonPassSpike
Mach-O 64-bit executable arm64
```

**The App Intents metadata extractor ran and produced what we want.** From
`BatonPassSpike.app/Metadata.appintents/extract.actionsdata`:

```json
"SendClipboardIntent": {
  "openAppWhenRun": false,
  "supportedModes": 1,                      // .background
  "isDiscoverable": true,
  "parameters": [{
    "name": "text",
    "inputConnectionBehavior": 2,           // .connectToPreviousIntentResult
    "valueType": { "primitive": { "wrapper": { "typeIdentifier": 0 } } },
    "resolvableInputTypes": [ ... 3 entries ... ]
  }]
}
```

This is the strongest static evidence available without a device: the system
toolchain has read the intent and recorded it as a background-mode action with a
String-typed parameter that auto-connects to the previous action's result.

⚠️ **`resolvableInputTypes` has three entries, not one.** The parameter's
declared type is the String primitive, but Shortcuts is willing to coerce two
other types (one scalar, one array) into it. That is the leading-zero risk, and
it lives on the Shortcuts side where app code cannot reach it. Mitigation is a
`Text` action in the shortcut (SHORTCUT-SETUP.md step 4.2) plus the receiver's
type check. The app cannot guarantee this on its own.

**Receiver works and detects the failure mode it exists to detect:**

```
text type    : str   <-- must be 'str'
utf8 hex     : 30 31 32 33 34 35
leading zero : YES
```
```
text type    : int   <-- must be 'str'
!! FAIL: text was not a JSON string — it was coerced on the way in
```

**Tailnet path is live.** `relay-mac` is `100.64.0.10` (matches the default
endpoint); `ping 100.64.0.30` reaches the iPhone, 10–847 ms (wake latency).

## 3. Blocker Rui must clear first

**Xcode cannot deploy to the device on this Mac.** The iOS platform component is
not installed:

```
$ xcodebuild -showdestinations -scheme BatonPassSpike
{ platform:iOS, name:i12, error:iOS 26.2 is not installed. }
```

`xcrun simctl list runtimes` is also empty. Fix: `xcodebuild -downloadPlatform iOS`
(multi-GB). This is why the build above had to be driven with `-target` and
`SYMROOT` rather than `-scheme` — `-scheme` needs a run destination and there is
none. The project itself is fine; `xcodebuild -list` resolves the scheme.

## 4. UNVERIFIED, and why

Everything in this section is unverified because there is no iPhone attached to
this machine and no developer signing identity in play. None of it can be
substituted with a simulator.

| Claim | Why it is open |
|---|---|
| Shortcuts' `Get Clipboard` raises no "Allow Paste" alert | **The whole hypothesis rests on this.** It is about the Shortcuts app's own clipboard access, which Apple does not document plainly. Widely reported to be silent for user-run shortcuts; not confirmed by me, on this device, on this iOS version. |
| A background intent launches a force-terminated app | Expected for user-initiated intents (unlike background refresh or silent push, which force-quit suppresses), but not documented as a guarantee. |
| Networking is permitted inside `perform()` | No documented prohibition, and the awaited-async shape is the intended one. Unproven here. |
| The execution budget exceeds a 10 s request | Apple publishes no number. 10 s should be comfortably inside it. Assumption. |
| Back Tap fires while the device is locked | Unknown. Likely restricted. |
| Which Keychain class is readable from a locked-device background run | This is why `KeychainProbe` exists — it logs both classes on every invocation. It answers the question only when run. |
| Local Network prompt | Tailscale routes 100.x over a `utun` packet tunnel, which normally sidesteps the local-network privacy gate. `NSLocalNetworkUsageDescription` is in Info.plist anyway so a prompt is a visible event rather than a silent connection failure. |
| Cold-boot-before-first-unlock behaviour | `UserDefaults` and the app container are Data Protection class C by default (available after first unlock). Before first unlock, config reads may fail. Untested. |

## 5. On-device test matrix

Run the receiver in a visible terminal throughout. Tick only what you saw.
For every row, record what appeared on the phone *and* what the receiver logged —
a missing POST and a failed POST are different results.

**Setup**
- [ ] `xcodebuild -downloadPlatform iOS` completed
- [ ] App installed on `iphone-example`, developer cert trusted
- [ ] Endpoint saved as `http://100.64.0.10:8787/clip`
- [ ] **Seed keychain items** tapped once in the app
- [ ] In-app manual probe with `012345` reaches the receiver (proves the network
      path before Shortcuts is involved)
- [ ] Shortcut built per SHORTCUT-SETUP.md, bound to Back Tap → Double Tap

**The matrix**

- [ ] **Leading-zero string integrity.** Copy `012345`. Back Tap. Receiver must
      show `text type : str`, `utf8 hex : 30 31 32 33 34 35`, `leading zero : YES`.
      *Fail if* `text type : int` or the hex starts `31`.
- [ ] **First-run permission prompts.** On the very first Back Tap, write down
      every alert, in order, verbatim. Specifically: is there an **"Allow Paste"**
      alert? If yes, note which app title it carries.
- [ ] **Cold start.** Reboot the phone. Unlock. Do **not** open BatonPassSpike.
      Copy a code. Back Tap. Receiver must log the POST.
- [ ] **Force-terminated app.** Open the app, swipe it away in the app switcher,
      copy, Back Tap. Receiver must log the POST.
- [ ] **Concurrent invocations.** Back Tap twice in quick succession, twice over.
      Receiver should show distinct `#seq` entries, one per gesture. Record
      duplicates and drops.
- [ ] **Unlocked.** The normal case. Should work; this is the honest target from
      `PLAN.md` §1.2.
- [ ] **Locked.** Lock the screen. Back Tap. Record: does Back Tap fire at all?
      Does it demand unlock? Does the POST arrive? Any of those is a valid answer;
      silence is the one to look out for.
- [ ] **Keychain accessibility class.** After a locked-state attempt *and* an
      unlocked one, open the app and read the log. Each invocation logs
      `keychain WhenUnlockedThisDeviceOnly=… AfterFirstUnlockThisDeviceOnly=…`.
      `status=-25308` is `errSecInteractionNotAllowed` — that class was
      unreadable in that state. **Record both classes in both states.** This
      decides where the T1 group key can live.
- [ ] **The intent awaits the POST.** Restart the receiver with `--delay 8`.
      Back Tap. The shortcut must stay busy ~8 s and report success only after
      the receiver answers. *Fail if* it reports success immediately.
- [ ] **Failure is surfaced, not swallowed.** Restart with `--fail 500`. Back Tap.
      Shortcuts must show an error. *Fail if* it reports success.
- [ ] **Network timeout.** Restart with `--delay 30` (request timeout is 10 s).
      Back Tap. Expect a timeout error surfaced within ~10 s, and a `FAIL` line
      in the in-app log.
- [ ] **Tailscale reconnection mid-send.** Turn Tailscale off on the phone.
      Back Tap → expect a surfaced failure, fast (`waitsForConnectivity` is off).
      Turn Tailscale back on, Back Tap again → expect success. Note how long the
      tunnel takes to be usable after reconnect; that latency is a real-world
      first-send-of-the-day cost.
- [ ] **User cancellation.** While a `--delay 30` send is in flight, cancel the
      shortcut (Shortcuts banner / Dynamic Island). Record whether the POST still
      arrives at the receiver. If it does, cancellation does not stop the send —
      which matters once the payload is a real secret.

**Then also, for S2 (not S1):** end-to-end latency Back Tap → POST logged, and a
failure rate over ~30 real invocations across a day.

## 6. Honest read on the hypothesis

**Likely to hold for the unlocked case. Unlikely to hold locked. One genuine
unknown remains, and it is not in the app.**

The part the app controls is settled: it never links a pasteboard symbol, so the
iOS 16 paste alert cannot originate here, and the foreground-read restriction
does not apply to code that performs no read. The intent is recorded by Apple's
own extractor as a background-mode action with a String parameter. Networking
inside an awaited `perform()` is the shape AppIntents is designed for.

The unknown moved, it did not disappear. It now sits in Shortcuts: whether
`Get Clipboard`, invoked by Back Tap, reads the pasteboard without prompting.
That is a property of a first-party app under user invocation and is not
something app code can influence, guarantee, or work around. If it prompts, S1's
premise is wrong in a way no amount of app-side work fixes, and the ladder
applies. My expectation is that it does not prompt — user invocation of a
shortcut is itself the consent gesture, which is the same logic that makes
`UIPasteControl` promptless — but expectation is not evidence and I have none.

Second-order concerns, in rough order of how likely they are to bite:

1. **Locked device.** Expect this to fail, and expect the failure to be in Back
   Tap or Shortcuts rather than in the app. `PLAN.md` §1.2 already scopes the
   honest claim to "while unlocked", so this is a confirmation, not a surprise.
   The one thing that must not happen is a *silent* failure.
2. **Cold-start latency.** The system has to launch the app process, run the
   intent, and complete a tunnel round trip. If S2 finds this slow, the lever is
   an **App Intents Extension** target — a lighter process than launching the
   full app — rather than a design change.
3. **Keychain under lock.** `WhenUnlockedThisDeviceOnly` will fail a locked-device
   background run. If locked sends turn out to matter,
   `AfterFirstUnlockThisDeviceOnly` is the only viable class, and that is a real
   weakening of at-rest protection that should be a deliberate T1 decision, not a
   default. The probe answers this empirically.
4. **Leading zero.** The extracted metadata shows Shortcuts will coerce types into
   this parameter. The `Text` action guard should hold, but this needs the
   explicit test, not an assumption.

### Fallback ladder (`TASKS.md` S1), evaluated

1. **Networking in the intent fails → intent encrypts, returns ciphertext,
   Shortcut POSTs it.** Viable and cheap. The intent already returns
   `ReturnsValue<String>`; Shortcuts' *Get Contents of URL* can POST a body.
   Confidentiality is unchanged — only ciphertext crosses into Shortcuts. The
   real cost is that failure handling and retries move into the shortcut, where
   they are harder to make correct, and awaiting-the-POST becomes Shortcuts'
   problem. **I do not expect to need this.**
2. **Background execution itself fails → foreground app + `UIPasteControl`.**
   Costs the "no app switch" half of the target and turns one gesture into
   several. Same confidentiality. Correct as a last resort.
3. **Never plaintext relay traffic; never clipboard text in a launch URL.**
   Respected. ⚠️ Note this spike *does* send plaintext over HTTP with
   `NSAllowsArbitraryLoads` — deliberately, because crypto is T1 — and both the
   plaintext and the ATS exception must die with the spike. Do not carry either
   into T5.

No improvised fourth rung was needed. Nothing found here suggests the hypothesis
is impossible as specified.

## 7. Notes for T5

- `openAppWhenRun` is deprecated from iOS 26 in favour of `supportedModes`. Both
  are declared here; T5 should raise the deployment target and drop the old one.
- Deployment target is iOS 17.0, `SWIFT_VERSION = 5.0`. T5 should move to the
  Swift 6 language mode deliberately, with strict concurrency considered.
- `SpikeLog` deliberately records only the *shape* of the text (length, first
  character, all-digits) and never the text itself. The on-device log must not
  become a clipboard history. The receiver holds the plaintext for this spike
  only.
- A free-provisioned build expires after 7 days.
- Consider an App Intents Extension target if S2 shows cold-start latency is poor.
