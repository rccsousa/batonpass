# T2 attack artefacts

Proof-of-concept code for `../T2-FINDINGS.md`. Separable from the spec; nothing
here is part of the deliverable envelope.

| path | finding | run |
|---|---|---|
| `cs/` A1 | F2 — spec's min frame 49 vs true 61 | `cd cs && dotnet run -- a1` |
| `cs/` A2 | F3 — `\|now - timestamp_ms\|` over uint64 (C# side) | `dotnet run -- a2` |
| `cs/` A3 | F6 — refutes SPEC §7's `tampered_header` claim | `dotnet run -- a3` |
| `cs/` A4 | fuzz of the *shipped* reference receiver (found nothing) | `dotnet run -- a4` |
| `swift/` a1 | F2 — same bug, Swift traps (SIGTRAP, `try?` cannot catch) | `swiftc -O -o attack attack.swift && ./attack a1` |
| `swift/` a2 | F3 — Swift traps on a 1 ms clock-ahead frame | `./attack a2` |
| `replay/` R1 | F1 — replay from clock skew alone | `python3 replay_sim.py` |
| `replay/` R2 | F9 — tailnet NTP flushes the dedup cache | (same script) |
| `replay/` R3 | dedup exhaustion by the relay: **not possible** | (same script) |
| `replay/` R4 | F11 — crash window kills the §5 retry rule | (same script) |
| `replay/` R5 | F9 — fail-closed has no recovery path | (same script) |

`swift/a1` and `swift/a2` are expected to exit 133 (SIGTRAP). That is the result.
