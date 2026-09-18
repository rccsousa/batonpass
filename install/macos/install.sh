#!/usr/bin/env bash
# BatonPass macOS installer. Idempotent: safe to re-run.
set -euo pipefail

BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$OFF" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*"; }
die()  { bad "$*"; exit 1; }

ask() {
  local prompt="$1"
  if [[ ! -t 0 ]]; then return 1; fi
  read -r -p "  $prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

PREFIX="${BATONPASS_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/batonpass"
PLIST="$HOME/Library/LaunchAgents/co.subvisual.batonpass.plist"
LOGDIR="$HOME/Library/Logs/BatonPass"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

say ""
say "${BOLD}BatonPass — macOS install${OFF}"
say ""

# ---------------------------------------------------------------- 1. Tailscale
say "${BOLD}1. Tailscale${OFF}"

TS=""
for candidate in \
  /Applications/Tailscale.app/Contents/MacOS/Tailscale \
  /usr/local/bin/tailscale \
  /opt/homebrew/bin/tailscale
do
  [[ -x "$candidate" ]] && TS="$candidate" && break
done

if [[ -z "$TS" ]]; then
  bad "Tailscale is not installed."
  say ""
  say "  BatonPass carries API keys and TOTP codes between your machines and has"
  say "  no transport of its own: it relies on the tailnet for encryption and for"
  say "  device identity. There is no useful way to continue without it."
  say ""
  say "  Install one of:"
  say "    Mac App Store   https://apps.apple.com/app/tailscale/id1475387142"
  say "    Homebrew        brew install --cask tailscale"
  say "    Direct          https://tailscale.com/download/mac"
  say ""
  if command -v brew >/dev/null 2>&1 && ask "Install via Homebrew now?"; then
    brew install --cask tailscale
    TS=/Applications/Tailscale.app/Contents/MacOS/Tailscale
    [[ -x "$TS" ]] || die "Install finished but the binary is not where expected."
  else
    die "Install Tailscale, then re-run this script."
  fi
fi
ok "found at $TS"

# Logged in and up? `status` exits non-zero when logged out or stopped.
if ! "$TS" status >/dev/null 2>&1; then
  warn "Tailscale is installed but not connected."
  say ""
  say "  Run:  $TS up"
  say "  (opens a browser to authenticate this machine into your tailnet)"
  say ""
  if ask "Run 'tailscale up' now?"; then
    "$TS" up || die "tailscale up failed."
  else
    die "Connect Tailscale, then re-run this script."
  fi
fi
ok "connected"

SELF_JSON="$("$TS" status --json 2>/dev/null)" || die "Could not read tailnet status."
SELF_IP="$(printf '%s' "$SELF_JSON" | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')"
SELF_NAME="$(printf '%s' "$SELF_JSON" | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin)["Self"]["HostName"])')"
STABLE_ID="$("$TS" whois --json "$SELF_IP" 2>/dev/null | /usr/bin/python3 -c 'import sys,json;print(json.load(sys.stdin)["Node"]["StableID"])')" \
  || die "Could not resolve this machine's tailnet identity."

ok "this machine is ${BOLD}$SELF_NAME${OFF} ($SELF_IP)"
ok "StableID ${BOLD}$STABLE_ID${OFF}"

# ------------------------------------------------------------------- 2. Relay
say ""
say "${BOLD}2. Relay${OFF}"

RELAY_HOST="${BATONPASS_RELAY_HOST:-}"
if [[ -z "$RELAY_HOST" ]]; then
  if [[ -t 0 ]]; then
    read -r -p "  Relay host:port (e.g. 100.64.0.20:4000): " RELAY_HOST
  else
    die "Set BATONPASS_RELAY_HOST, or run this interactively."
  fi
fi
[[ -n "$RELAY_HOST" ]] || die "No relay host given."

if /usr/bin/nc -z -G 3 "${RELAY_HOST%%:*}" "${RELAY_HOST##*:}" 2>/dev/null; then
  ok "reachable at $RELAY_HOST"
else
  warn "cannot reach $RELAY_HOST right now"
  say "    Not fatal — the agent retries. But check the relay is running and that"
  say "    this machine's StableID is on its allowlist:"
  say ""
  say "      $STABLE_ID"
fi

# --------------------------------------------------------------------- 3. Build
say ""
say "${BOLD}3. Build${OFF}"

command -v swift >/dev/null 2>&1 || die "Swift not found. Install Xcode or the Command Line Tools."

( cd "$REPO/agents/macos" && swift build -c release >/dev/null 2>&1 ) \
  || die "Build failed. Run 'swift build -c release' in agents/macos to see why."

mkdir -p "$PREFIX/bin" "$LOGDIR"
cp "$REPO/agents/macos/.build/release/BatonPass" "$BIN"
chmod 755 "$BIN"
ok "installed $BIN"

VECTORS="$REPO/crypto/vectors.json"
if [[ -f "$VECTORS" ]] && "$BIN" --verify-vectors "$VECTORS" | grep -q "0 failed"; then
  ok "conformance vectors pass"
else
  die "Conformance vectors FAILED. Refusing to install an agent that cannot read the wire format."
fi

# ----------------------------------------------------------------------- 4. Key
say ""
say "${BOLD}4. Group key${OFF}"

if security find-generic-password -s batonpass -a group-key >/dev/null 2>&1; then
  ok "already in the login keychain"
else
  warn "no group key on this machine"
  say ""
  say "  ${BOLD}First device?${OFF}  Generate one:"
  say "      $BIN --generate-key"
  say ""
  say "  ${BOLD}Adding a device?${OFF}  Import the key from a device that has it:"
  say "      $BIN --import-key <64-hex-chars>"
  say ""
  say "  Type it in by hand, or use a password manager. Never send the key through"
  say "  BatonPass itself: it would be encrypted under the old key and delivered to"
  say "  every enrolled device, including one you may be trying to revoke."
  say ""
  if ask "Generate a new key now (only if this is the FIRST device)?"; then
    "$BIN" --generate-key
  else
    warn "skipping — the agent will not start until a key is present"
  fi
fi

# ------------------------------------------------------------------ 5. Autostart
say ""
say "${BOLD}5. Autostart${OFF}"

# LaunchAgent, not LaunchDaemon: a daemon runs outside the Aqua session and
# cannot reach the pasteboard at all.
mkdir -p "$(dirname "$PLIST")"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>co.subvisual.batonpass</string>
  <key>ProgramArguments</key>
  <array><string>$BIN</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>BATONPASS_RELAY</key><string>ws://$RELAY_HOST/socket/websocket?vsn=2.0.0</string>
    <key>BATONPASS_GROUP</key><string>${BATONPASS_GROUP:-home}</string>
    <key>BATONPASS_SENDER</key><string>${BATONPASS_SENDER:-1}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$LOGDIR/batonpass.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/batonpass.err</string>
</dict>
</plist>
PLISTEOF

launchctl bootout "gui/$(id -u)/co.subvisual.batonpass" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl kickstart -k "gui/$(id -u)/co.subvisual.batonpass" 2>/dev/null || true
ok "LaunchAgent loaded — starts at login"

say ""
say "${BOLD}Done.${OFF}"
say ""
say "  Enroll this machine on the relay by adding its StableID to the allowlist:"
say "      ${BOLD}$STABLE_ID${OFF}   ($SELF_NAME)"
say ""
say "  Logs:     tail -f $LOGDIR/batonpass.log"
say "  Stop:     launchctl bootout gui/$(id -u)/co.subvisual.batonpass"
say "  Start:    launchctl bootstrap gui/$(id -u) $PLIST"
say "  Remove:   $(dirname "${BASH_SOURCE[0]}")/uninstall.sh"
say ""
