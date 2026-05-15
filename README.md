# switchbot-keypad-bridge

ESPHome external component that lets an ESP32 impersonate a **SwitchBot Lock**
BLE peripheral so a SwitchBot Keypad can pair to it and deliver encrypted
`lock` / `unlock` commands. The bridge decrypts the frames in-place and
republishes them to Home Assistant — without requiring a real lock.

The decoded commands are exposed two ways:

| Surface | When to use |
|---|---|
| `event` entity (`keypad:`) | Standard ESPHome entity, surfaces in HA as `event.<device>_keypad` with `lock`/`unlock` event types. Zero-config, great for dashboards. |
| ESPHome triggers (`on_lock` / `on_unlock`) | Drive every other action: HA events, service calls, local relays, notifications. The unlock trigger receives `method` (`pin`/`fingerprint`) and `index` (credential slot). |

## Repository layout

```
.
├── switchbot-keypad-bridge.yaml             # Device configuration
├── secrets.example.yaml                     # Template for secrets.yaml
├── tools/
│   ├── generate_key.py                      # Generate a random shared key
│   ├── pair_keypad.py                       # Pair the keypad with the bridge
│   └── requirements.txt                     # Python dependencies for the tools
└── components/switchbot_keypad_bridge/      # The external component
    ├── __init__.py                          # ESPHome codegen / schema
    ├── automation.h                         # on_lock / on_unlock triggers
    ├── switchbot_keypad_bridge.h
    └── switchbot_keypad_bridge.cpp
```

## Setup

**Prerequisites:** Python 3.10+, a Bluetooth adapter, and the keypad already added to your SwitchBot account.

### 1. Generate a shared key

```bash
python tools/generate_key.py
```

Copy the printed 32-character value — you will need it in the next two steps.

### 2. Create `secrets.yaml`

Copy `secrets.example.yaml` to `secrets.yaml` and fill in your details:

```yaml
wifi_ssid: "your_network_name"
wifi_password: "your_wifi_password"
ota_password: "a_strong_ota_password"
switchbot_shared_key: "PASTE_KEY_FROM_STEP_1_HERE"
```

### 3. Flash the ESP32

```bash
pip install esphome
esphome run switchbot-keypad-bridge.yaml
```

After the device boots, note the BLE address printed in the log:

```
[C][switchbot_keypad_bridge]: BLE address: XX:XX:XX:XX:XX:XX
```

It is also exposed as the **BLE MAC** sensor on the Home Assistant device page.

### 4. Install the pairing tool

```bash
pip install -r tools/requirements.txt
```

### 5. Pair the keypad

```bash
python tools/pair_keypad.py KEYPAD_MAC ESP_MAC SHARED_KEY --user your@email.com
```

| Argument | Where to find it |
|---|---|
| `KEYPAD_MAC` | SwitchBot app → open the keypad device → ... → **Device Info** → **BLE Address** |
| `ESP_MAC` | The BLE address from step 3 (log or Home Assistant) |
| `SHARED_KEY` | The key generated in step 1 |

You will be prompted for your SwitchBot account password. When the script finishes, the keypad LED turns green — press any key to confirm commands arrive in Home Assistant.

### Stream logs

```bash
esphome logs switchbot-keypad-bridge.yaml
```

## Wiring up automations

### Who unlocked the door?

The `on_unlock` trigger carries two pieces of information about every unlock event:

| Parameter | Type | Values |
|---|---|---|
| `method` | `std::string` | `"pin"` or `"fingerprint"` |
| `index` | `int` | Numeric ID of the credential, or `-1` if unknown |

**`index` is the slot number the SwitchBot app assigns automatically when you add a PIN or fingerprint** — the first credential you add gets index `0`, the second gets `1`, and so on. This lets you distinguish between users: if family members each have their own PIN or fingerprint, you can trigger different automations based on who is at the door.

Use `homeassistant.event` to forward both values to Home Assistant as event data, then build per-user automations entirely in HA without recompiling the firmware.

```yaml
switchbot_keypad_bridge:
  shared_key: !secret switchbot_shared_key
  keypad:
    name: "Keypad"

  on_unlock:
    # Forward method and index to Home Assistant as a custom event.
    - homeassistant.event:
        event: esphome.switchbot_keypad_unlock
        data:
          method: !lambda 'return method;'
          index: !lambda 'return to_string(index);'

    # Or react directly on the ESP32 — e.g. different action per user.
    - if:
        condition:
          lambda: 'return method == "fingerprint" && index == 0;'
        then:
          - logger.log: "Welcome home, owner"

  on_lock:
    - logger.log: "Locked"
```

On the Home Assistant side, create an automation (**Settings → Automations → New automation → ... → Edit in YAML**) and paste:

```yaml
alias: Notify on keypad unlock
triggers:
  - trigger: event
    event_type: esphome.switchbot_keypad_unlock
actions:
  - action: notify.mobile_app
    data:
      message: >
        Door unlocked via {{ trigger.event.data.method }}
        (credential #{{ trigger.event.data.index }})
```

`trigger.event.data.method` is `pin` or `fingerprint`; `trigger.event.data.index` is the slot number the SwitchBot app assigned when the credential was added.

To react only to a specific credential, add a `conditions:` block. The following example sends a notification only when the first fingerprint (index `0`) is used:

```yaml
alias: Welcome home — owner fingerprint
triggers:
  - trigger: event
    event_type: esphome.switchbot_keypad_unlock
conditions:
  - condition: template
    value_template: >
      {{ trigger.event.data.method == 'fingerprint' and
         trigger.event.data.index == '0' }}
actions:
  - action: notify.mobile_app
    data:
      message: Welcome home!
```

Create one automation per credential to send tailored notifications or trigger different actions for each family member.

## Configuration reference

| Option         | Type        | Required | Description |
|----------------|-------------|----------|-------------|
| `shared_key`   | string      | yes      | 32-character hex AES-128 session key. |
| `keypad`       | event       | no       | Configures the standard ESPHome `event` entity. |
| `ble_mac`      | text_sensor | no       | Diagnostic text sensor with the BLE peripheral address (the MAC the keypad must pair against). |
| `on_lock`      | auto        | no       | Triggered on every `lock` command. |
| `on_unlock`    | auto        | no       | Triggered on every `unlock` command, parameters `(std::string method, int index)`. |

## Security

`shared_key` is the symmetric AES-128 secret your physical SwitchBot setup
already trusts. Treat it like a password — keep it in `secrets.yaml`,
never commit it to git.

## Implementation notes

- The component uses NimBLE (via the `esp-nimble-cpp` managed component) and
  the mbed-TLS PSA Crypto API that already ships with ESP-IDF. No additional
  Python or C++ dependencies are required.
- AES-CTR is symmetric: the same `aes_ctr_xcrypt_` primitive handles both
  encryption (responses) and decryption (incoming commands).
- The bridge advertises on the ESP32's native public BLE address. Pair the
  keypad against that address — either read it from `dump_config` at boot
  (`BLE address: ...`) or, more conveniently, expose it to Home Assistant
  via the optional `ble_mac:` diagnostic text sensor.
- The BLE address is the Wi-Fi MAC plus 2 (ESP32 derives one MAC per
  interface from the same base), so the value Home Assistant displays on
  the device card is *not* the one the keypad sees.
- `FINAL_VALIDATE_SCHEMA` raises a hard error if `esp32_ble`,
  `esp32_ble_tracker`, `esp32_improv`, etc. are present in the config —
  NimBLE cannot coexist with ESPHome's BLE stack.
