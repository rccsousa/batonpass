# Relay contract (T3)

Frozen. The relay is a **dumb ciphertext fan-out**. This document is what T4
implements and what T5/T6/T8 code against.

## Non-capabilities (these are the point)

The relay **cannot**:

- decrypt anything — it holds no key and links no AEAD
- store anything — no database, no queue, no disk persistence, no catch-up
- run a shell — no `System.cmd`, no `System.shell`, no ports to executables,
  with one exception: `tailscale whois` for peer identity (§2)
- see plaintext, ever, including in logs, error paths and crash dumps

If a change to the relay would require any of the above, the change is wrong.

## 1. Transport

Phoenix WebSocket at `/socket`, one topic: `clipboard:<group_id>`.

`group_id` is an opaque identifier shared by enrolled devices. It is **not** a
secret and grants nothing — authorization is §2. It exists so one relay can
serve more than one device set without them colliding.

Frames are **binary**. A client pushes an event named `"frame"` whose payload is
the raw envelope from `crypto/SPEC.md`. The relay broadcasts it verbatim to every
*other* subscriber on the topic.

The relay does not parse the envelope beyond its length. It does not read the
version byte, the epoch, the sender, or the timestamp. It moves opaque bytes.

## 2. Authorization

Every connection passes the `tailscale whois` gate from spike S4 before the
socket is established. Rejection is a connection refusal, not an error frame.

Three independent conditions, **all** required:

1. the peer resolves to a tailnet identity at all
2. the node carries **no tags** — a tagged node is shared infrastructure
3. the node's `StableID` is on the explicit allowlist

Any failure, including `tailscaled` being unreachable, is a refusal. **Fail
closed.** The relay binds to the tailnet interface only, never `0.0.0.0`.

`StableID` is the allowlist key: tailnet IPs get reassigned and MagicDNS names
get renamed, but `StableID` survives both.

## 3. Limits

| limit | value | on violation |
|---|---|---|
| max frame | 65,597 bytes | close the connection |
| min frame | 61 bytes | close the connection |
| max frames/sec per connection | 20 | close the connection |
| max subscribers per topic | 16 | refuse the join |

The frame-size cap is **normative for the relay**, not delegated to "the
transport" (T2/F12). The relay is the one component every frame passes through
and it is untrusted; it must reject oversized frames **without buffering them**.

Rate limiting is a safety valve against a malfunctioning agent, not a security
control — an enrolled device is trusted by definition.

## 4. Logging

**Metadata only.** Permitted: connection open/close, peer `StableID`, peer name,
rejection reason, frame *size*, error class.

**Forbidden everywhere, including error and crash paths:** frame bytes, any
slice of them, anything derived from them. A frame is never interpolated into a
log line, never attached to an exception, never included in a Phoenix crash
report.

Because the relay never decrypts, "don't log plaintext" is automatic. The rule
above exists so ciphertext does not accumulate on the one host the design
deliberately distrusts.

## 5. Delivery semantics

- **Broadcast to others, never echo to sender.** The sender already has it, and
  an echo would trip the receiver's own loop suppression.
- **Best effort. No persistence, no catch-up, no retry.** A device that is
  offline misses the item. This is deliberate: a reconnecting device that
  silently overwrote the current clipboard with a stale value is worse than
  missing it.
- **No ordering guarantee** beyond what one WebSocket connection provides.
  Receivers dedup on `(epoch, sender_id, event_id)` and do not rely on order.
- Backpressure: if a subscriber's send queue exceeds 64 frames, **drop that
  subscriber's connection.** Do not buffer, do not block the broadcast. A slow
  consumer must not become the relay's memory problem.

## 6. Control plane

`GET /health` — returns `200` with build info and subscriber counts. Metadata
only, and subject to the same allowlist as the socket.

Enrollment (approve/revoke a `StableID`) is **configuration**, not an API. T10
adds a UI over it. There is no endpoint that mutates the allowlist, because the
relay is the least trusted machine in the system and must not be able to widen
its own access.

**Key material never passes through the relay**, including through any page it
serves. That host can replace the JavaScript on any page it hosts, so a
relay-served key-entry form is not a safe transport even over TLS.
