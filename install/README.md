# Installing BatonPass

One install per machine, then it runs at login and you stop thinking about it.

There is no agentless option. Writing a clipboard requires code running inside
that user's logged-in session on every OS in this project — see
`spikes/s3-windows-clipboard/FINDINGS.md`, where a process in Windows session 0
wrote and read a clipboard successfully that **no user could see**. Anything
"agentless" would mean the relay holding credentials to execute commands on your
machines, which is strictly more capability than a clipboard agent and would make
the least-trusted host the most powerful one.

## macOS

```
install/macos/install.sh
```

Checks, in order, and stops with instructions rather than failing obscurely:

1. **Tailscale installed** — offers `brew install --cask tailscale` if Homebrew
   is present, otherwise prints the App Store and direct-download links.
2. **Tailscale connected** — offers to run `tailscale up`.
3. **This machine's tailnet identity** — prints the `StableID` you must add to
   the relay allowlist.
4. **Relay reachable** — warns but continues, since the agent retries.
5. **Builds and runs the 26 conformance vectors.** Refuses to install an agent
   that cannot read the wire format.
6. **Group key** — generates one for the first device, or tells you how to import
   it on the others.
7. **LaunchAgent** — not a LaunchDaemon: a daemon runs outside the Aqua session
   and cannot reach the pasteboard at all.

Re-running is safe.

    tail -f ~/Library/Logs/BatonPass/batonpass.log     # what it is doing
    install/macos/uninstall.sh                          # remove it
    install/macos/uninstall.sh --purge-key              # and forget the key

## The group key

Every enrolled device holds the same 32-byte key. Generate it on one device:

    batonpass --generate-key

and import it on the others:

    batonpass --import-key <64-hex-chars>

**Type it in by hand, or use a password manager.** Never send the key through
BatonPass itself — it would be encrypted under the *old* key and delivered to
every currently enrolled device, including one you may be trying to revoke. That
is the single most important rule in `crypto/SPEC.md` §6.

The key is stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so it is
not backed up: a restore onto another device cannot resurrect a revoked epoch.

## Enrollment

The relay holds the allowlist. A machine is in the clipboard group only if its
`StableID` is listed there — being on the tailnet is not sufficient, which is the
whole point. The installer prints the `StableID` at the end.

Tagged nodes are rejected before the allowlist is even consulted, so a shared or
tagged machine cannot join even if someone lists it by mistake.
