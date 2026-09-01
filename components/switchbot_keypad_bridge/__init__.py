"""ESPHome integration: SwitchBot Keypad Bridge.

This external component emulates a SwitchBot Lock BLE peripheral so a linked
SwitchBot Keypad can deliver encrypted unlock/lock commands. The bridge
decrypts the frames in-place using mbed-TLS / PSA Crypto and exposes the
decoded commands through two surfaces:

- A standard ESPHome ``event`` entity (``Lock``/``Unlock``/``Doorbell`` types).
- ESPHome automation triggers (``on_lock`` / ``on_unlock`` / ``on_doorbell``).
  ``on_unlock`` receives the unlock ``method`` and credential ``index`` as
  arguments; the others take none.

The AES session key is generated on the device on first boot and kept in
NVS — it is never part of the YAML configuration.
"""

from __future__ import annotations

import gzip
import logging
from pathlib import Path

import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome import automation
from esphome.components import button, event, sensor, text_sensor
from esphome.components.esp32 import (
    add_idf_component,
    add_idf_sdkconfig_option,
    include_builtin_idf_component,
)
from esphome.const import (
    CONF_ID,
    CONF_TRIGGER_ID,
    DEVICE_CLASS_BATTERY,
    ENTITY_CATEGORY_CONFIG,
    ENTITY_CATEGORY_DIAGNOSTIC,
    STATE_CLASS_MEASUREMENT,
    UNIT_PERCENT,
)
from esphome.core import CORE, HexInt

LOGGER = logging.getLogger(__name__)

CODEOWNERS = ["@pierluigizagaria"]
DEPENDENCIES = ["esp32"]
AUTO_LOAD = ["event", "text_sensor", "button", "sensor"]
MULTI_CONF = False

CONF_KEYPAD_ACTION = "keypad_action"
CONF_KEYPAD = "keypad"
CONF_LINKED_LOCK = "linked_lock"
CONF_KEYPAD_BATTERY_LEVEL = "keypad_battery_level"
CONF_LOCK_BATTERY_LEVEL = "lock_battery_level"
CONF_BATTERY_SCAN_INTERVAL = "battery_scan_interval"
CONF_RESET_BUTTON = "reset_button"
CONF_REPORT_LOCKED_BUTTON = "report_locked_button"
CONF_ON_LOCK = "on_lock"
CONF_ON_UNLOCK = "on_unlock"
CONF_ON_DOORBELL = "on_doorbell"
CONF_PAIRING_UI = "pairing_ui"

# Auto-generated id for the progmem array that carries the embedded UI.
CONF_PAIRING_UI_HTML_ID = "pairing_ui_html_id"

# The setup wizard is a single, self-contained HTML file living next to
# this module. It doubles as a browser-openable design preview.
PAIRING_UI_HTML = Path(__file__).parent / "pairing_ui.html"


switchbot_keypad_bridge_ns = cg.esphome_ns.namespace("switchbot_keypad_bridge")
SwitchbotKeypadBridge = switchbot_keypad_bridge_ns.class_(
    "SwitchbotKeypadBridge", cg.Component
)
ResetButton = switchbot_keypad_bridge_ns.class_("ResetButton", button.Button)
ReportLockedButton = switchbot_keypad_bridge_ns.class_(
    "ReportLockedButton", button.Button
)
LockTrigger = switchbot_keypad_bridge_ns.class_(
    "LockTrigger", automation.Trigger.template()
)
UnlockTrigger = switchbot_keypad_bridge_ns.class_(
    "UnlockTrigger", automation.Trigger.template(cg.std_string, cg.int_)
)
DoorbellTrigger = switchbot_keypad_bridge_ns.class_(
    "DoorbellTrigger", automation.Trigger.template()
)


def _deprecated_pairing_ui(value):
    """The on-device wizard is now always compiled in. Accept ``true`` for
    backwards compatibility (with a deprecation warning) and reject ``false``
    explicitly so users who tried to disable it learn what changed."""
    v = cv.boolean(value)
    if v is False:
        raise cv.Invalid(
            "pairing_ui: false is no longer supported — the on-device setup "
            "wizard is always compiled in. Remove this option."
        )
    LOGGER.warning(
        "switchbot_keypad_bridge: the 'pairing_ui' option is deprecated and "
        "can be removed — the wizard is now always available."
    )
    return v


CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(SwitchbotKeypadBridge),
        cv.Optional(CONF_KEYPAD_ACTION): event.event_schema(icon="mdi:gesture-tap"),
        cv.Optional(CONF_KEYPAD): text_sensor.text_sensor_schema(
            icon="mdi:lock-smart",
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        cv.Optional(CONF_LINKED_LOCK): text_sensor.text_sensor_schema(
            icon="mdi:key",
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        # The keypad broadcasts its battery in its BLE advertisement; the
        # bridge picks it up with a short background scan once per interval.
        cv.Optional(CONF_KEYPAD_BATTERY_LEVEL): sensor.sensor_schema(
            unit_of_measurement=UNIT_PERCENT,
            device_class=DEVICE_CLASS_BATTERY,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            accuracy_decimals=0,
        ),
        cv.Optional(CONF_LOCK_BATTERY_LEVEL): sensor.sensor_schema(
            unit_of_measurement=UNIT_PERCENT,
            device_class=DEVICE_CLASS_BATTERY,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            accuracy_decimals=0,
        ),
        cv.Optional(
            CONF_BATTERY_SCAN_INTERVAL, default="15min"
        ): cv.positive_time_period_milliseconds,
        cv.Optional(CONF_PAIRING_UI): _deprecated_pairing_ui,
        cv.Optional(CONF_RESET_BUTTON): button.button_schema(
            ResetButton,
            entity_category=ENTITY_CATEGORY_CONFIG,
            icon="mdi:restart",
        ),
        cv.Optional(CONF_REPORT_LOCKED_BUTTON): button.button_schema(
            ReportLockedButton,
            entity_category=ENTITY_CATEGORY_CONFIG,
            icon="mdi:lock-check",
        ),
        cv.GenerateID(CONF_PAIRING_UI_HTML_ID): cv.declare_id(cg.uint8),
        cv.Optional(CONF_ON_LOCK): automation.validate_automation(
            {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(LockTrigger)}
        ),
        cv.Optional(CONF_ON_UNLOCK): automation.validate_automation(
            {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(UnlockTrigger)}
        ),
        cv.Optional(CONF_ON_DOORBELL): automation.validate_automation(
            {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(DoorbellTrigger)}
        ),
    }
).extend(cv.COMPONENT_SCHEMA)


_INCOMPATIBLE_COMPONENTS = [
    "esp32_ble",
    "esp32_improv",
    "esp32_ble_beacon",
    "esp32_ble_client",
    "esp32_ble_tracker",
    "esp32_ble_server",
]


def _final_validate(config):
    full_config = fv.full_config.get()

    if CORE.is_esp32:
        conflicting = [c for c in _INCOMPATIBLE_COMPONENTS if c in full_config]
        if conflicting:
            raise cv.Invalid(
                "switchbot_keypad_bridge uses NimBLE directly and is incompatible with "
                "the ESPHome BLE stack. Remove these components from your configuration: "
                + ", ".join(conflicting)
            )

        if "psram" not in full_config:
            LOGGER.warning(
                "switchbot_keypad_bridge: consider enabling PSRAM if available — "
                "NimBLE benefits from the extra heap."
            )

    # The setup wizard binds to port 80 and reuses ESPHome's USE_WEBSERVER
    # flag for HA discovery. Both clash with the official `web_server:`
    # component, which also defines USE_WEBSERVER and (by default) listens
    # on 80.
    if "web_server" in full_config:
        raise cv.Invalid(
            "switchbot_keypad_bridge cannot coexist with the `web_server:` "
            "component — both bind to port 80 and both define USE_WEBSERVER. "
            "Remove `web_server:`."
        )

    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    if keypad_conf := config.get(CONF_KEYPAD_ACTION):
        keypad = await event.new_event(
            keypad_conf, event_types=["Lock", "Unlock", "Doorbell"]
        )
        cg.add(var.set_keypad_event(keypad))

    if keypad_sensor_conf := config.get(CONF_KEYPAD):
        sens = await text_sensor.new_text_sensor(keypad_sensor_conf)
        cg.add(var.set_keypad_text_sensor(sens))

    if linked_lock_conf := config.get(CONF_LINKED_LOCK):
        sens = await text_sensor.new_text_sensor(linked_lock_conf)
        cg.add(var.set_linked_lock_text_sensor(sens))

    if battery_conf := config.get(CONF_KEYPAD_BATTERY_LEVEL):
        batt = await sensor.new_sensor(battery_conf)
        cg.add(var.set_keypad_battery_level_sensor(batt))

    if lock_battery_conf := config.get(CONF_LOCK_BATTERY_LEVEL):
        batt = await sensor.new_sensor(lock_battery_conf)
        cg.add(var.set_lock_battery_level_sensor(batt))

    if config.get(CONF_KEYPAD_BATTERY_LEVEL) or config.get(CONF_LOCK_BATTERY_LEVEL):
        cg.add(
            var.set_battery_scan_interval(
                config[CONF_BATTERY_SCAN_INTERVAL].total_milliseconds
            )
        )

    if button_conf := config.get(CONF_RESET_BUTTON):
        btn = await button.new_button(button_conf)
        await cg.register_parented(btn, config[CONF_ID])

    if button_conf := config.get(CONF_REPORT_LOCKED_BUTTON):
        btn = await button.new_button(button_conf)
        await cg.register_parented(btn, config[CONF_ID])

    # Make Home Assistant show the "Visit Device" link on the device page.
    # ESPHome's api component fills `webserver_port` in DeviceInfoResponse
    # iff USE_WEBSERVER is defined; HA uses that field to construct the URL.
    # We piggy-back on the same flag so the setup wizard gets discovered
    # without requiring the user to also enable `web_server:` in YAML.
    cg.add_define("USE_WEBSERVER")
    cg.add_define("USE_WEBSERVER_PORT", 80)

    # Bake the setup wizard's HTML into the firmware image as a
    # gzip-compressed PROGMEM array (~4x smaller; served with
    # Content-Encoding: gzip). `pairing_ui.html` is the single source of
    # truth — no generated header to commit, no build step to run by hand.
    # mtime=0 keeps the gzip header (and thus the build) reproducible.
    html_bytes = gzip.compress(PAIRING_UI_HTML.read_bytes(), mtime=0)
    html_arr = cg.progmem_array(
        config[CONF_PAIRING_UI_HTML_ID], [HexInt(b) for b in html_bytes]
    )
    cg.add(var.set_pairing_ui_html(html_arr, len(html_bytes)))

    for trig_conf in config.get(CONF_ON_LOCK, []):
        trig = cg.new_Pvariable(trig_conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trig, [], trig_conf)

    for trig_conf in config.get(CONF_ON_UNLOCK, []):
        trig = cg.new_Pvariable(trig_conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(
            trig, [(cg.std_string, "method"), (cg.int_, "index")], trig_conf
        )

    for trig_conf in config.get(CONF_ON_DOORBELL, []):
        trig = cg.new_Pvariable(trig_conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trig, [], trig_conf)

    # NimBLE C++ wrapper, pulled as ESP-IDF managed component (no Python deps).
    add_idf_component(
        name="esp-nimble-cpp",
        repo="https://github.com/h2zero/esp-nimble-cpp.git",
        ref="2.5.0",
    )

    # Switch the BT stack from Bluedroid to NimBLE.
    add_idf_sdkconfig_option("CONFIG_BT_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_BLUEDROID_ENABLED", False)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_MAX_CONNECTIONS", 3)

    # LWIP's default pool of 10 sockets is too tight for this device: the HA
    # API, a log-stream client, mDNS, the wizard's httpd sessions and the
    # cloud TLS client can all hold sockets at once — the TLS connect then
    # fails with "failed to create socket" / "sock < 0".
    add_idf_sdkconfig_option("CONFIG_LWIP_MAX_SOCKETS", 16)

    # Silence the NimBLE logger to keep heap and serial noise to a minimum.
    add_idf_sdkconfig_option("CONFIG_NIMBLE_CPP_LOG_LEVEL", 0)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_LOG_LEVEL", 0)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_LOG_LEVEL_NONE", True)

    # The cloud client calls https://*.switchbot.net — pull in mbedTLS's
    # built-in certificate bundle so esp_crt_bundle_attach() finds the CAs
    # that sign those domains. Without CONFIG_MBEDTLS_CERTIFICATE_BUNDLE the
    # TLS handshake fails with ESP_ERR_HTTP_CONNECT. Also tell ESP-IDF that
    # this user component depends on esp_http_client and esp-tls so the
    # headers and link symbols are visible to cloud_client.cpp.
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL", True)
    include_builtin_idf_component("esp_http_client")
    include_builtin_idf_component("esp-tls")
