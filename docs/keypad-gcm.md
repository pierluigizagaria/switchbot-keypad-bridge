# GCM session implementation

See the README for configuration, model coverage and security limits.
CTR remains the default; GCM is an explicit standalone option.

## Architecture and compatibility

The existing ORIGINAL (Keypad/Touch) and VISION (Vision/Pro) pairing
families are preserved. GCM accepts their known slot identifiers and
pins the selected slot for the session. Hardware verification covers
Keypad Touch firmware 3.1 on ESP32-C3-DevKitM-1 only. Other models and
firmware require community testing of the application protocol as well
as cryptography. VISION emits an informational warning. Commands outside
the currently implemented Lock, PIN, NFC and fingerprint exchange are
rejected; face, palm and doorbell have not been verified in GCM.

The tested Touch announces CTR when provisioned by either the official
app or this wizard. Its action sessions use GCM when configured.
The wizard's existing CTR provisioning confirmation handling is inherited.
A device that negotiates GCM during provisioning needs further implementation
and testing. No automatic fallback between action-session modes is performed.

Shared key and device identity retain the original preference records.
Upgrade alone preserves association across reboot. Reset rotates the key,
invalidates sessions and clears both links. It also works with the wizard
already open, provided no pairing or relay job is running.

## Session processing

GcmSession owns validation, nonce progression, duplicate response caching and
completion. The bridge owns BLE transport, state and event publication.
Incoming frames are bound to the active connection and selected slot.
A new connection receives a random 96-bit nonce. Only a supported action
can start the exchange; later commands must be state polls. Each new
request advances the counter, while replies use that request's nonce.

The latest identical request gets its cached ciphertext response without
advancing the counter or repeating the action. Invalid tags, stale counters,
a changed slot or unsupported command invalidate the exchange. The session
is bounded to ten seconds and sixteen polls. A failed notification resets
the session and suppresses its event. A mismatched connection cannot finish it.

CTR publishes immediately after decoding. GCM conservatively waits for an
authenticated poll and disconnect before releasing one action through the
same entities and callbacks. Cryptographic verification is performed before
replying; the wait is an implementation policy for incomplete exchanges.
It adds the keypad's connection lifetime to event latency and can suppress
an event if disconnect occurs after the timeout. It is retained pending
evidence and review of an alternative completion policy. Neither disconnect
nor a sent notification proves the keypad displayed success.

Final state replies reflect the requested Lock or Unlock. Mechanical
telemetry fields and part of the action acknowledgment retain representative
values from successful native captures. Complete mechanical emulation is
outside this contribution.

## Regression checks

Run from the repository root:

```sh
sh tests/run_gcm_session_tests.sh
sh tests/run_lock_session_tests.sh
sh tests/run_keypad_state_tests.sh
python -m unittest discover -s tests -p 'test_*.py'
```

The Python configuration checks require ESPHome. GCM and CTR host session
tests substitute cryptographic functions; they test state transitions,
slot binding, credential indices, malformed requests, duplicates, stale
counters, expiry, connection ownership, exactly-once completion and rejection
limits. They do not execute the ESP-IDF AES backend. The state tests exercise
the lock/rearm logic. Compile with ESPHome and perform the hardware checks
below to validate integration.

## Final hardware checklist

On ESP32-C3-DevKitM-1 and Keypad Touch 3.1:

- Associate once using the wizard, and verify the displayed keypad name.
- Verify green indication and exactly one HA event for both registered
  fingerprints, PIN and NFC, with the expected method and index.
- Verify Lock, repeated Lock, and unlock while already unlocked.
- Repeat an action after an idle period and after restarting the bridge.
- Reset with the wizard open, associate again, and repeat one unlock.
- For an existing installation with a saved lock link, confirm the GCM
  warning and suppressed actions until links are explicitly reset.

Functional checks on the earlier GCM implementation passed for these
credentials and after reboot. Repeat them on the final upstream candidate.
No additional model hardware is required for this acceptance checklist.
Community results for other ORIGINAL and VISION models are welcome.
