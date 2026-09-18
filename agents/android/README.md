# BatonPass for Android

A native Kotlin client for Android 10 or later. It speaks the existing Phoenix
binary protocol and uses the same ChaCha20-Poly1305 envelopes as the desktop and
iPhone clients. No relay changes are needed.

## Build and install

Install JDK 17 and Android SDK Platform 35 through Android Studio. Open this
directory in Android Studio, or point `ANDROID_HOME` at your SDK and run:

```sh
cd agents/android
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The checked-in Gradle wrapper downloads its pinned distribution and verifies
its SHA-256 checksum. The debug APK is for personal testing, not a signed release
for distribution. With multiple devices connected, select one using
`adb -s <serial> install -r ...`.

## Enroll

1. Install and connect Tailscale on the phone. Permit access to the relay's TCP
   port in your tailnet ACLs.
2. From the relay host, run `tailscale whois --json <phone-tailnet-ip>`. Add the
   phone's `Node.StableID` to `BATONPASS_ALLOWED_STABLE_IDS` and restart the relay.
   The phone must satisfy the configured owner-login check and must not be tagged.
3. Open BatonPass → **Enrollment / relay settings**. Enter the relay's Tailscale
   IPv4 and port, for example `100.64.0.10:4000`, the existing group, an unused
   numeric sender ID, the current epoch, and the existing 64-hex group key.
4. Import the key out of band. Never send it through BatonPass. Choose **Save**
   and wait for **Connected · receiving while open**.

The Android MVP accepts literal Tailscale IPv4 addresses only, not MagicDNS,
public hosts, reverse proxies, or arbitrary URLs. WebSocket metadata travels
inside Tailscale; clipboard content is additionally encrypted end to end.

## Send and receive

- **Send clipboard** reads plain text only when you tap it while the app has
  focus. It preserves whitespace and leading-zero codes.
- In another app, select text → **Share → BatonPass**, then tap **Send this text**.
  Sharing opens a preview; it never sends automatically. You can also type text.
- To receive, keep BatonPass open and focused, then copy on a connected desktop.
  Accepted text goes to the Android clipboard, marked sensitive to suppress
  supported system previews. Paste it into another app normally.
- Leaving BatonPass closes its socket. Returning reconnects. A dialog covering
  the activity also prevents clipboard writes while the activity lacks focus.
- **Queued to relay** means accepted by the local WebSocket queue. It is not a
  delivery receipt. The relay has no acknowledgment, history, retry queue, or
  catch-up; offline receivers miss items. No automatic retry resends a payload.

Android 10+ restricts clipboard reads to the focused app or default keyboard.
This client does not request Accessibility, root, keyboard, notification, or
background-service privileges. It does not watch the clipboard in the background.
See [Android clipboard restrictions](https://developer.android.com/about/versions/10/privacy/changes#clipboard-data).

## Security and recovery

Enrollment and replay files are AES-GCM encrypted with a device-local Android
Keystore key, kept under `noBackupFilesDir`, and excluded from cloud backup and
device transfer. Screenshots, saved text-field state, and autofill are disabled
for the secret-entry surface. The app does not log keys, payloads, or received text.

The receiver authenticates before checking freshness, enforces the current epoch,
and persists acceptance before updating the clipboard. It rejects duplicates,
stale frames, malformed text, and a full 4,096-entry cache. A separate persisted
counter detects a replay-file rollback. Missing or unreadable state and detected
clock discontinuities pause reception until explicit recovery. This is not a
hardware rollback-resistant counter and does not defend against a compromised
device that can restore all private files together.

After correcting the phone's clock, **Resume after clock correction** explicitly
flushes the dedup cache. The confirmation explains that still-fresh old frames
could be accepted again. It never resumes on a timer. If enrollment or the
Keystore key is lost, clear app storage and enroll again out of band; do not
restore old app data. Clearing storage also discards replay protection.

Saving an unchanged identity or editing the relay endpoint retains replay state.
To rekey, pause the other devices, revoke any removed device at the relay, import
a fresh key out of band, and increase the epoch on every retained device. Android
requires both a new key and a higher epoch; group and sender stay fixed. The app
shows an encryption count for the epoch; this count is informational, not a limit.

Only the most recent received text's SHA-256 digest is retained for local loop
suppression; plaintext history is not stored. The input preview is memory-only
and is not restored after activity recreation.

## Verification

```sh
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
# With a dedicated emulator or test phone connected:
./gradlew :app:connectedDebugAndroidTest
```

Unit tests verify all 26 shared crypto vectors, exact outgoing bytes, malformed
Phoenix frames, enrollment validation, UTF-8 limits, replay across restarts,
inclusive freshness boundaries, cache capacity, clock jumps, and storage failure.
Instrumentation tests exercise the Android crypto provider against the same
vectors, real Keystore persistence/rekey, a local WebSocket relay fixture, join
gating, explicit disconnect, and the share activity. Test enrollment uses a
separate storage namespace and is deleted afterwards.

On 2026-09-18, a live smoke test verified the real macOS clipboard watcher →
Phoenix relay → Android 16 emulator clipboard → paste into an Android text field.
The pasted text matched exactly, including leading-zero digits, Unicode, spaces,
and a newline. A negative control with the Mac agent stopped confirmed that
emulator clipboard sharing did not bypass BatonPass. The test used a separate
relay port and disposable group key; temporary enrollment and processes were
removed afterwards. The temporary smoke harness is not part of the checked-in
instrumentation suite.

The emulator used the Mac's Tailscale connection and identity, so this does not
verify independent Android Tailscale enrollment. Android-to-Mac live delivery,
physical-device clipboard UX, and OEM lifecycle behavior still require a
real-device smoke test. First open
BatonPass, copy a unique value on desktop, and paste on the phone; then use
**Send clipboard** and paste on desktop. Background reception is intentionally
outside this MVP.
