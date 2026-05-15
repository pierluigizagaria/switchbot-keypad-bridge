#!/usr/bin/env python3
"""Generate a random 16-byte shared key for switchbot-keypad-bridge.

Copy the printed value into secrets.yaml as switchbot_shared_key,
then run this key through the pairing script after flashing.
"""

import secrets

print(secrets.token_hex(16).upper())
