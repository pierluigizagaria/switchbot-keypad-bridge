# Standalone Keypad Touch GCM

Set `keypad_crypto_mode: gcm` under `switchbot_keypad_bridge`.
The default remains CTR for existing installations. The GCM mode targets
the original Keypad Touch with firmware 3.1. It provides fingerprint, PIN,
NFC and Lock through the existing entities and callbacks.

Pair using the normal setup wizard. This keypad announces CTR for
provisioning, as observed with the official app. Actions after pairing
use GCM. The shared key and device identity survive reboot. Reset allows
reassociation even while the wizard is open and waits for active BLE jobs.

GCM mode supports standalone use. Physical-lock forwarding requires CTR.
An existing physical-lock link must be reset before selecting standalone GCM.
Use the mode with the keypad model and firmware above; other device families
have separate protocol behavior.

The bridge verifies a two-byte tag prefix on each incoming request.
Each connection receives a random nonce, which advances for each new
command. One action and at most sixteen state polls are allowed within
ten seconds. Exact repeats of the latest request receive the cached reply.
Other stale requests invalidate the session. Successful actions publish
one event after a verified state poll and disconnect. Lock/unlock response
state follows the requested action; unknown mechanical telemetry fields
retain representative native capture values.

## Verification

The investigation build was verified on ESP32-C3 with both fingerprints,
PIN, NFC, Lock, repeated actions and restart. This clean implementation
requires hardware acceptance after installation. Check both the keypad
indication and one corresponding HA event for each action.

Run `sh tests/run_gcm_session_tests.sh` to test the actual session class.
The host test substitutes cryptographic and radio functions to isolate
protocol behavior. It covers duplicate replies, stale requests, wrong
connections, invalid tags, incomplete sessions, timeouts, credential indices
and exactly-once completion. Run the existing CTR and state tests as well.

## Security scope

This implementation follows the observed native schedule, including the
same nonce and key in request and reply and sixteen-bit transmitted tags.
Those are security limitations of the native protocol. Functional
compatibility and host regression tests do not establish complete security
parity with the native device under an active attacker. The original
CTR provisioning confirmation handling remains inherited. Its timeout
behavior is a known limitation, outside this change.

## Moving from the investigation branch

Change the external component source to
`github://robertoamd90/switchbot-keypad-bridge@feat/keypad-gcm`.
Keep `keypad_crypto_mode: gcm`. Remove `gcm_diagnostics`,
`gcm_lock_slot_test` and an on_boot lambda that calls
`run_crypto_selftest()`, if those investigation options are present.
Other entities and callbacks retain their existing configuration.
Saved shared key and keypad identity use the original preference records;
upgrading alone does not require Reset or a new association.
