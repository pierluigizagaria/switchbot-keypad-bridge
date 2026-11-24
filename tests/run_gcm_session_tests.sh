#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=$(mktemp "${TMPDIR:-/tmp}/switchbot-gcm-session.XXXXXX")
trap 'rm -f "$BIN"' EXIT HUP INT TERM
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror \
  -I"$ROOT/tests/stubs" -I"$ROOT" \
  "$ROOT/components/switchbot_keypad_bridge/gcm_session.cpp" \
  "$ROOT/components/switchbot_keypad_bridge/lock_protocol.cpp" \
  "$ROOT/tests/gcm_session_test.cpp" -o "$BIN"
"$BIN"
