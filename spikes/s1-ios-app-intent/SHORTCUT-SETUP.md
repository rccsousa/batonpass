# S1 — Shortcut setup, step by step

Everything here is done by hand on the iPhone. None of it has been executed —
see `FINDINGS.md` for what that means.

---

## 0. Prerequisite on the Mac (`relay-mac`) — currently NOT satisfied

Xcode 26.2 is installed but the **iOS platform component is not**, so Xcode
cannot deploy to a device or run a simulator:

```
$ xcodebuild -showdestinations -scheme BatonPassSpike
  { platform:iOS, name:i12, error:iOS 26.2 is not installed. }
```

Fix it once, before anything else:

```
xcodebuild -downloadPlatform iOS
```

(or Xcode → Settings → Components → iOS 26.2). Multi-GB download.

## 1. Start the receiver on the Mac

```
cd spikes/s1-ios-app-intent
python3 receiver/receiver.py
```

It prints the URLs to try and prefers the tailnet one:

```
S1 receiver on 0.0.0.0:8787  (POST /clip, GET /health)
  try: http://100.64.0.10:8787/clip
```

Leave it running in a visible terminal — it is the only place the full round trip
is observable.

Two probe flags used later in the test matrix:

- `--delay 30` — hold the HTTP response 30s (network-timeout / "does it await?" probe)
- `--fail 500` — always answer HTTP 500 (failure-surfacing probe)

## 2. Install the app on the iPhone

1. Open `BatonPassSpike.xcodeproj` in Xcode.
2. Select the `BatonPassSpike` target → Signing & Capabilities.
3. Set **Team** to your Apple ID. The bundle id `co.subvisual.batonpass.spike`
   may need changing if it collides; any unique id is fine.
4. Plug in / pair `iphone-example`, select it as the run destination, Run.
5. First install with a free Apple ID: Settings → General → VPN & Device
   Management → trust the developer certificate. A free-account build **expires
   after 7 days** — fine for a spike, note it for T5.

## 3. Point the app at the Mac

Launch the app once. Confirm the endpoint reads
`http://100.64.0.10:8787/clip`, tap **Save endpoint**, then tap
**Seed keychain items** (this plants the two probe items the locked-device test
reads back).

Tap **Send (same path as the intent)** with the default text `012345`. The
receiver should log a `text type : str` line with `leading zero : YES`. This
proves the network path before Shortcuts is involved at all.

## 4. Build the Shortcut

Shortcuts app → **+** (new shortcut).

1. Search actions for **Clipboard** → add **Get Clipboard**.
2. Search for **Text** → add the **Text** action. Tap its field, then insert the
   **Clipboard** magic variable (the variable chip above the keyboard) so the
   action contains nothing but that variable.

   > This action is not decoration. Shortcuts types its values, and a clipboard
   > holding `012345` can be carried as a Number, which drops the leading zero.
   > The `Text` action forces a text coercion before the value reaches the app.
   > The extracted intent metadata confirms the parameter accepts more than one
   > input type, so Shortcuts will coerce rather than refuse.

3. Search for **Send Text to BatonPass** (it appears under the BatonPassSpike
   app) → add it. Because the parameter declares
   `inputConnectionBehavior: .connectToPreviousIntentResult`, it should
   auto-fill with the **Text** action's output. **Verify this** — if it bound to
   the `Get Clipboard` output instead, tap the field and re-point it at the
   `Text` variable.
4. Rename the shortcut to **BatonPass Send** (title bar → Rename).
5. Done.

Expected final shape:

```
Get Clipboard
Text            [Clipboard]
Send Text to BatonPass   Text: [Text]
```

## 5. Bind it to Back Tap

Settings → Accessibility → Touch → **Back Tap** → **Double Tap** → scroll to the
Shortcuts section → select **BatonPass Send**.

## 6. First run

Copy `012345` somewhere (Notes is fine), then double-tap the back of the phone.

Record precisely what appears on screen and in what order. Candidates, none of
which are confirmed:

- a Shortcuts banner ("BatonPass Send")
- an "Allow Paste" alert (would mean the hypothesis is in trouble — see the
  FINDINGS fallback section)
- a Local Network permission prompt
- nothing at all

The receiver terminal is the ground truth for what actually arrived.
