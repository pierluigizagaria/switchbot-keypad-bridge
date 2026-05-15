"""ESPHome integration: SwitchBot Keypad Bridge.

This external component emulates a SwitchBot Lock BLE peripheral so a paired
SwitchBot Keypad can deliver encrypted unlock/lock commands. The bridge
decrypts the frames in-place using mbed-TLS / PSA Crypto and exposes the
decoded commands through two surfaces:

- A standard ESPHome ``event`` entity (``lock``/``unlock`` types).
- ESPHome automation triggers (``on_lock`` / ``on_unlock``) which receive
  the unlock ``method`` and credential ``index`` as arguments.
"""

from __future__ import annotations

import logging
import re

import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome import automation
from esphome.components import event, text_sensor
from esphome.components.esp32 import add_idf_component, add_idf_sdkconfig_option
from esphome.const import CONF_ID, CONF_TRIGGER_ID, ENTITY_CATEGORY_DIAGNOSTIC
from esphome.core import CORE

LOGGER = logging.getLogger(__name__)

CODEOWNERS = ["@pierluigizagaria"]
DEPENDENCIES = ["esp32"]
AUTO_LOAD = ["event", "text_sensor"]
MULTI_CONF = False

CONF_SHARED_KEY = "shared_key"
CONF_KEYPAD = "keypad"
CONF_BLE_MAC = "ble_mac"
CONF_ON_LOCK = "on_lock"
CONF_ON_UNLOCK = "on_unlock"

_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _validate_shared_key(value):
    value = cv.string_strict(value)
    if not _HEX32_RE.match(value):
        raise cv.Invalid(
            f"Invalid shared_key: expected 32 hexadecimal characters (got {len(value)})."
        )
    return value.upper()


switchbot_keypad_bridge_ns = cg.esphome_ns.namespace("switchbot_keypad_bridge")
SwitchbotKeypadBridge = switchbot_keypad_bridge_ns.class_(
    "SwitchbotKeypadBridge", cg.Component
)
LockTrigger = switchbot_keypad_bridge_ns.class_(
    "LockTrigger", automation.Trigger.template()
)
UnlockTrigger = switchbot_keypad_bridge_ns.class_(
    "UnlockTrigger", automation.Trigger.template(cg.std_string, cg.int_)
)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(SwitchbotKeypadBridge),
        cv.Required(CONF_SHARED_KEY): _validate_shared_key,
        cv.Optional(CONF_KEYPAD): event.event_schema(icon="mdi:dialpad"),
        cv.Optional(CONF_BLE_MAC): text_sensor.text_sensor_schema(
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:bluetooth",
        ),
        cv.Optional(CONF_ON_LOCK): automation.validate_automation(
            {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(LockTrigger)}
        ),
        cv.Optional(CONF_ON_UNLOCK): automation.validate_automation(
            {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(UnlockTrigger)}
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

    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_shared_key(config[CONF_SHARED_KEY]))

    if keypad_conf := config.get(CONF_KEYPAD):
        keypad = await event.new_event(keypad_conf, event_types=["lock", "unlock"])
        cg.add(var.set_keypad_event(keypad))

    if ble_mac_conf := config.get(CONF_BLE_MAC):
        sens = await text_sensor.new_text_sensor(ble_mac_conf)
        cg.add(var.set_ble_mac_text_sensor(sens))

    for trig_conf in config.get(CONF_ON_LOCK, []):
        trig = cg.new_Pvariable(trig_conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trig, [], trig_conf)

    for trig_conf in config.get(CONF_ON_UNLOCK, []):
        trig = cg.new_Pvariable(trig_conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(
            trig, [(cg.std_string, "method"), (cg.int_, "index")], trig_conf
        )

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

    # Silence the NimBLE logger to keep heap and serial noise to a minimum.
    add_idf_sdkconfig_option("CONFIG_NIMBLE_CPP_LOG_LEVEL", 0)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_LOG_LEVEL", 0)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_LOG_LEVEL_NONE", True)
