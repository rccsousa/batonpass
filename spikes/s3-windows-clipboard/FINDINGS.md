# S3 — Windows clipboard access

**Status: RESOLVED.** All five checks decided by observation on `windows-pc`
(Windows 10.0.26200), in both a non-interactive SSH session and the real desktop
session. The council's native-vs-PowerShell deadlock is settled on evidence.

Raw evidence committed alongside this file:
- `observed-session1.json` — full probe run, real desktop session (session 1)
- `observed-gui-read.json` — native read of a clipboard item produced by Notepad

## Verdict: native Win32. PowerShell is disqualified on correctness.

| Input | Native | PowerShell |
|-------|--------|------------|
| plain ascii | PASS | PASS |
| emoji 👨‍👩‍👧‍👦 (ZWJ sequence) | PASS | **FAIL** |
| cjk 漢字かなカナ😀 | PASS | **FAIL** |
| combining é | PASS | **FAIL** |
| crlf | PASS | PASS |
| lf | PASS | PASS |

Native: 6/6 byte-exact. PowerShell: 3/6.

**PowerShell fails silently.** On every corrupted input it reported
`powershellExitCode: 0` and `powershellStatus: true`. It claims success while
mangling the payload. A TOTP code survives it; a password containing an accented
character does not, with no error anywhere.

Identical results in session 0 and session 1, so this is not a session artifact.

Astra argued for native on injection-surface grounds and Fable argued for a
fixed-script PowerShell stdin writer. Astra's conclusion holds, but the
deciding evidence turned out to be correctness rather than injection surface —
the PowerShell path as written is not merely riskier, it is wrong.

## Reading another application's clipboard item

`observed-gui-read.json`, captured by copying in Notepad and then reading with
`Probe2.exe --dump` (read-only, no write):

```
text : 😊すばらしいcafé
cp   : U+1F60A U+3059 U+3070 U+3089 U+3057 U+3044 U+0063 U+0061 U+0066 U+00E9
hex  : F0 9F 98 8A | E3 81 99 E3 81 B0 E3 82 89 E3 81 97 E3 81 84 | 63 61 66 C3 A9
```

11 UTF-16 units, 10 codepoints, 24 UTF-8 bytes — consistent, the surrogate pair
accounts for 11 vs 10. Astral emoji, kana and a precomposed é all round-trip with
zero loss. Every other observation in this spike is the probe reading back its
own writes; this is the only one against a foreign producer, and it is clean.

## Session scoping: confirmed, and the failure mode is silent

| | SSH (session 0) | Desktop (session 1) |
|---|---|---|
| `userInteractive` | false | true |
| `processSessionId` | 0 | 1 |
| `activeConsoleSessionId` | 1 | 1 |
| `isInActiveConsoleSession` | **false** | **true** |
| `interactive_session_required` | INCONCLUSIVE | **PASS** |

The important part: **in session 0 the native clipboard calls still succeeded.**
Writes returned success, reads round-tripped, nothing errored — against a
window-station-local clipboard that no user can see.

That is the dangerous shape. A misconfigured agent does not crash or log an
error; it silently syncs into a void. This confirms PLAN.md §2's session-scoping
requirement from the other direction, and makes the `isInActiveConsoleSession`
health check a hard requirement rather than a nicety.

## Clipboard sequence number: works, but the delta is not 1

```
session 0: before 89  -> 94  -> 99    (delta 5, 5)
session 1: before 534 -> 539 -> 544   (delta 5, 5)
```

`GetClipboardSequenceNumber` advances reliably on every write, including the
process's own writes — but by **5 per write**, not 1, consistently across both
sessions. Change detection must test *strictly increasing*. Any implementation
comparing against `previous + 1` will miss every change.

## Contention: handled

A separate STA thread held the clipboard open while the writer retried.
`writeStatus: true`, `retryCount: 8`, `backoffBaseMs: 100`,
`resultAfterReleaseMatches: true`. `OpenClipboard` failing under contention is
the classic real-world bug here; exponential backoff with ~8 attempts clears it.

## Win+V clipboard history: ON, and it will retain your secrets

Read from the registry on `windows-pc`:

```
EnableClipboardHistory        : 1
CloudClipboardAutomaticUpload : (unset)
EnableCloudClipboard          : (unset)
```

History is enabled. Cloud sync is not. Without mitigation, every API key and TOTP
code BatonPass delivers to this machine is retained in Win+V.

**A per-item exclusion API does exist** — this spike originally declined to
assume one. Three registered clipboard formats, used by KeePass and KeePassXC:

| Format | Effect |
|--------|--------|
| `ExcludeClipboardContentFromMonitorProcessing` | excludes from history **and** cloud sync |
| `CanIncludeInClipboardHistory` = DWORD `0` | suppresses history only |
| `CanUploadToCloudClipboard` = DWORD `0` | suppresses cloud sync only |

`RegisterClipboardFormat(name)` then `SetClipboardData(fmt, handle)` inside the
same `OpenClipboard`/`EmptyClipboard` session as the payload.

This is the Windows analogue of macOS `.currentHostOnly` (see S5) — and unlike
that one it is documented. T6 must set all three on every write.

## Bug found and fixed in the probe

`WTSGetActiveConsoleSessionId` was declared as `[DllImport("wtsapi32.dll")]`. It
is exported by **kernel32.dll** despite the WTS prefix. The probe crashed with
`EntryPointNotFoundException` on first run. Fixed.

## Adapter contract (now evidence-backed, for T6)

- **Write**: `OpenClipboard` → `EmptyClipboard` → `HGLOBAL` UTF-16LE + NUL →
  `SetClipboardData(CF_UNICODETEXT)` → set the three exclusion formats →
  `CloseClipboard`. Retry `OpenClipboard` with exponential backoff, base 100 ms,
  ~8 attempts. Classify busy/locked as retryable.
- **Read**: `GetClipboardData(CF_UNICODETEXT)` → `GlobalLock` → decode UTF-16
  until NUL.
- **Change detect**: poll `GetClipboardSequenceNumber`, treat any strictly
  increasing value as a change. Never assume +1.
- **Health**: refuse to run when `processSessionId != activeConsoleSessionId`.
  Do not degrade quietly — the clipboard will appear to work.

## Runbook note

PowerShell's `>` redirection writes **UTF-16LE**, which doubles file size and
breaks UTF-8 parsers downstream. Use `| Out-File -Encoding utf8`.

## Remaining unverified

- Whether the three exclusion formats actually suppress Win+V retention on this
  machine. The API is documented and the formats are named correctly here, but
  this spike did not write them and observe the result. Verify during T6.
- Behaviour under a locked workstation.
- Behaviour with clipboard managers installed alongside.
