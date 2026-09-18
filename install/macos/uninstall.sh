#!/usr/bin/env bash
# Removes the agent. Leaves the group key alone unless --purge-key is given,
# because deleting it on the last device means the others must all be rekeyed.
set -euo pipefail

PREFIX="${BATONPASS_PREFIX:-$HOME/.local}"
PLIST="$HOME/Library/LaunchAgents/co.subvisual.batonpass.plist"

launchctl bootout "gui/$(id -u)/co.subvisual.batonpass" 2>/dev/null || true
rm -f "$PLIST" "$PREFIX/bin/batonpass"
echo "removed agent and LaunchAgent"

if [[ "${1:-}" == "--purge-key" ]]; then
  security delete-generic-password -s batonpass -a group-key >/dev/null 2>&1 || true
  echo "removed group key from the login keychain"
else
  echo "group key left in the keychain (pass --purge-key to remove it)"
fi
