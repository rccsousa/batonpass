# S4 — `tailscale whois` peer identity in Phoenix

**Status: PASSES acceptance.** 17 tests, 0 failures, including two integration
tests run against the live tailnet on this machine.

Acceptance criterion from TASKS.md was:

> a Plug that rejects any peer not on an explicit allowlist, with a test proving
> it fails closed.

Both delivered.

## What was built

- `lib/s4_tailscale_whois/whois.ex` — resolves a source IP to a tailnet identity
  (`stable_id`, `name`, `login_name`, `tags`). The shell-out is injectable so a
  downed daemon can be tested without stopping the real one.
- `lib/s4_tailscale_whois/plug.ex` — the gate. Assigns `:tailnet_identity` on
  success; 403 + `halt()` on every other path.
- `test/` — 17 tests. Run `mix test`; `mix test --only integration` hits the
  live tailnet.

## Findings

### 1. Allowlist on `StableID`, not IP and not hostname

`tailscale whois --json` returns `Node.StableID` (e.g. `nREDACTED03CNTRL` for
`windows-pc`). This is the stable node identifier. Tailnet IPs can be reassigned and
MagicDNS names can be renamed by the user; `StableID` survives both. Enrollment
should record `StableID`.

### 2. Tagged nodes are structurally distinguishable — this matters a lot

The shared lab server resolves as:

```
lab StableID: nREDACTED04CNTRL
lab Tags    : ['tag:lab']
UserProfile : tagged-devices
```

whereas a personal device resolves to the real account
(`owner@example.invalid`) with **no** tags.

This is stronger than the plan assumed. The machine you wanted excluded from
clipboard trust is identifiable by structure, not by a naming convention you
have to maintain. The Plug therefore rejects on three independent conditions,
any one of which is sufficient:

1. the node carries **any** tag,
2. the node's user is not the owner login,
3. the `StableID` is not explicitly allowlisted.

A test asserts that a tagged node is rejected **even when its StableID is on the
allowlist** — tags win. That ordering is deliberate: it means a future
mis-enrollment of the lab box still fails.

`eve-tether` is also `tagged-devices`, so it is covered by the same rule.

### 3. `whois` fails cleanly on an unknown peer

```
$ tailscale whois --json 8.8.8.8
exit=1, stdout empty, stderr "peer not found"
```

Non-zero exit with empty stdout. An earlier reading of `exit=0` was wrong — that
was the exit status of a `head` in the pipeline, not of `whois`. Verified
directly. This means the happy-path check (`{out, 0}`) is sufficient and there
is no need to string-match stderr.

### 4. Daemon-down must be handled explicitly

If the Tailscale binary is missing or `tailscaled` is not running, `System.cmd`
raises rather than returning non-zero. Unrescued, that would propagate as a 500
— which is still a denial, but by accident rather than by design. It is rescued
and converted to `{:error, {:whois_unavailable, reason}}` so the denial is
intentional and logged. A test covers it.

### 5. The IP is validated before it reaches argv

The source IP is parsed with `:inet.parse_address/1` and rejected if it is not a
bare address. `System.cmd` already passes argv without shell interpretation, so
this is redundant — deliberately so. Tests assert that `"100.1.1.1; rm -rf /"`
and `"$(whoami)"` are rejected *before* the resolver is invoked.

Note this is the one place `System.cmd/3` is appropriate: there is no payload,
only a validated argument. It is **not** appropriate for clipboard writes, which
need stdin — and `System.cmd/3` has no stdin option at all (see PLAN.md §8).

## Carried into T3/T4

- Enrollment stores `StableID`, not IP or name.
- The gate rejects tagged nodes unconditionally, before consulting the allowlist.
- The Plug must bind to the tailnet interface only. **Not covered by this spike**
  — binding is Phoenix endpoint configuration, and is listed in T4.
- Logging is identity metadata only. The `deny/2` path logs the rejection reason
  and never touches the request body. T3's logging policy must keep that true.

## Unverified

- Behaviour when `tailscaled` is running but the node is logged out. Not
  simulated; the rescue path should cover it but this is an inference, not an
  observation.
- Performance. `whois` is a subprocess per connection. Acceptable at
  connection-establishment frequency for a handful of devices; it would not be
  acceptable per-message. T3 should confirm the gate runs on channel join only.
- The hardcoded macOS binary path
  (`/Applications/Tailscale.app/Contents/MacOS/Tailscale`) is correct for this
  Mac and wrong for the Debian relay, where it is `/usr/bin/tailscale`. Make it
  configuration in T4.
