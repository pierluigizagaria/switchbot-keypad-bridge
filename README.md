# SwitchBot Keypad Bridge

> Use a **SwitchBot Keypad without a SwitchBot Lock** — pair it straight to an
> ESP32 and turn every PIN, fingerprint, NFC, and face unlock into a Home Assistant event.

<p align="center">
  <img src="docs/pairing.gif" alt="Pairing a SwitchBot Keypad through the on-device wizard" width="320">
</p>

An [ESPHome](https://esphome.io/) external component that makes an ESP32
impersonate a **SwitchBot Lock** over Bluetooth LE. A genuine SwitchBot Keypad
pairs to it and sends its usual encrypted `lock` / `unlock` frames — the bridge
decrypts them on the fly and hands them to Home Assistant. The keypad never
knows it isn't talking to a real lock.

## Why use it

- 🔓 **No SwitchBot Lock required** — repurpose a keypad as a standalone, fully
  local door/access controller.
- 📲 **On-device pairing wizard** — sign in to your SwitchBot account, pick the
  keypad, done. No Python script, no laptop, no BLE sniffing.
- 👤 **Knows who unlocked** — every unlock carries the method (`pin` /
  `fingerprint` / `nfc` / `face`) and the credential slot, so you can act per user.
- 🔐 **Keys never leave the device** — the AES-128 session key is generated on
  the ESP32 and stored in NVS; it is never in your YAML or git.
- 🧩 **Pure ESPHome** — exposes a standard `event` entity plus `on_lock` /
  `on_unlock` automation triggers. No cloud, no extra dependencies.

## Supported keypads

The pairing wizard identifies the keypad model **from its BLE advertisement** —
the same way the official [pySwitchbot](https://github.com/sblibs/pySwitchbot)
library does — and adapts the pairing protocol accordingly. Detection does not
depend on the cloud `device_type`/SKU string at all, so a keypad is found and
paired even if its SKU is one SwitchBot hasn't shipped before.

| Model | Protocol family | Status |
|---|---|---|
| SwitchBot Keypad Touch | Original | ✅ **Tested** |
| SwitchBot Keypad Vision | Vision | ✅ **Tested** |
| SwitchBot Keypad | Original | Supported — same protocol as Touch |
| SwitchBot Keypad Vision Pro | Vision | Supported — same protocol as Vision |

> Because the keypad is recognised from its live advertisement, keep it within
> ~2 m and powered while you run the wizard — out-of-range devices won't be
> listed.

## Quick start

**You need:** an ESP32 and a SwitchBot Keypad already added to your SwitchBot
account.

### 1. Create `secrets.yaml`

Copy `secrets.example.yaml` to `secrets.yaml` and fill in your details:

```yaml
wifi_ssid: "your_network_name"
wifi_password: "your_wifi_password"
ota_password: "a_strong_ota_password"
```

### 2. Flash the ESP32

```bash
pip install esphome
esphome run switchbot-keypad-bridge.yaml
```

### 3. Pair the keypad

On first boot — with no keypad paired — the device opens its **pairing wizard**
automatically. Open it in a browser at `http://<device-ip>/` (the IP is in the
boot log, or use Home Assistant's **Visit Device** link on the device page):

1. Sign in with your SwitchBot account.
2. Pick your keypad from the list.
3. Wait for the wizard to finish — it closes itself when done.

That's it. The keypad's name appears on the **Keypad** sensor and key presses
arrive in Home Assistant as `Lock` / `Unlock` events.

> **Re-pairing** — to switch to a different keypad, press the **Unpair** button
> in Home Assistant. The device forgets the current keypad, rotates its session
> key, and re-opens the pairing wizard right away — no reboot.

To stream logs at any time:

```bash
esphome logs switchbot-keypad-bridge.yaml
```

## Knowing who unlocked the door

Every `on_unlock` trigger carries two values:

| Parameter | Type | Values |
|---|---|---|
| `method` | `std::string` | `"pin"`, `"fingerprint"`, `"nfc"`, `"face"`, or `"unknown"` |
| `index` | `int` | Numeric ID of the credential slot |

**`index` is the slot the SwitchBot app assigns automatically when you add a
PIN, fingerprint, NFC card, or face** — the first credential gets index `0`, the second
`1`, and so on. Combined with `method`, it tells you exactly which family member
is at the door.

The cleanest pattern is to forward both values to Home Assistant as a custom
event with `homeassistant.event`, then build per-user automations entirely in HA
without recompiling the firmware:

```yaml
switchbot_keypad_bridge:
  keypad_action:
    name: "Action"

  on_unlock:
    # Forward method and index to Home Assistant as a custom event.
    - homeassistant.event:
        event: esphome.switchbot_keypad_unlock
        data:
          method: !lambda 'return method;'
          index: !lambda 'return to_string(index);'

    # Or react directly on the ESP32 — e.g. a different action per user.
    - if:
        condition:
          lambda: 'return method == "fingerprint" && index == 0;'
        then:
          - logger.log: "Welcome home, owner"

  on_lock:
    - logger.log: "Locked"
```

On the Home Assistant side, create an automation (**Settings → Automations → New
automation → ⋮ → Edit in YAML**) and paste:

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

To react only to a specific credential, add a `conditions:` block. This example
fires only for the first fingerprint (index `0`):

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

Create one automation per credential to send tailored notifications or trigger
different actions for each family member.

## Configuration reference

| Option | Type | Required | Description |
|---|---|---|---|
| `keypad_action` | event | no | Standard ESPHome `event` entity for keypad actions. Surfaces in HA as `event.<device>_action` with `Lock` / `Unlock` event types. |
| `keypad` | text_sensor | no | Text sensor whose state is the display name of the paired keypad (Configuration category; empty if none). |
| `unpair_button` | button | no | Button that forgets the paired keypad, rotates the session key and re-opens the pairing wizard (no reboot). |
| `on_lock` | automation | no | Triggered on every `lock` command. |
| `on_unlock` | automation | no | Triggered on every `unlock` command — parameters `(std::string method, int index)`. |

## How it works

### Security

The AES-128 session key is generated on the device on first boot, kept in NVS,
and injected into the keypad during pairing. It is never part of the YAML
configuration and never leaves the device. The **Unpair** button rotates it, so
a keypad paired before an unpair can no longer command the bridge afterwards.

### Implementation notes

- The component uses NimBLE (via the `esp-nimble-cpp` managed component) and the
  mbed-TLS PSA Crypto API that already ships with ESP-IDF. No additional Python
  or C++ dependencies are required.
- AES-CTR is symmetric: the same `aes_ctr_xcrypt_` primitive handles both
  encryption (responses) and decryption (incoming commands).
- At boot the bridge spoofs the chip's BLE address into SwitchBot's OUI
  (`B0:E9:FE:xx:xx:xx`), preserving the chip-unique last three bytes so every
  device still has a distinct identifier. The Keypad Vision filters scan results
  on this prefix and would otherwise ignore the bridge. Read the advertised
  address from the boot log (`Ready. Advertising on …`) — it is *not* the Wi-Fi
  MAC Home Assistant displays on the device card.
- `FINAL_VALIDATE_SCHEMA` raises a hard error if `esp32_ble`,
  `esp32_ble_tracker`, `esp32_improv`, etc. are present in the config — NimBLE
  cannot coexist with ESPHome's BLE stack.

## Support

If this project saved you the cost of a SwitchBot Lock — or just made your day —
consider buying me a coffee. It's a great way to say thanks and keep the work
going.

<p align="center">
  <a href="https://buymeacoffee.com/pierluigizagaria">
    <img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=&slug=pierluigizagaria&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" alt="Buy Me A Coffee">
  </a>
</p>
