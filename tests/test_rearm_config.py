"""Run with: python -m unittest discover -s tests -p test_rearm_config.py."""

import importlib.util
from pathlib import Path
import unittest

import esphome.config_validation as cv


COMPONENT = (
    Path(__file__).resolve().parents[1]
    / "components/switchbot_keypad_bridge/__init__.py"
)
spec = importlib.util.spec_from_file_location("switchbot_keypad_bridge", COMPONENT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class RearmConfigurationTest(unittest.TestCase):
    def test_existing_configuration_keeps_timer_disabled(self):
        config = bridge.CONFIG_SCHEMA({})
        self.assertEqual(config["auto_rearm_after"].total_milliseconds, 0)

    def test_custom_delay_and_explicit_disable(self):
        for value, expected in [("20s", 20000), ("1250ms", 1250), ("0s", 0)]:
            with self.subTest(value=value):
                config = bridge.CONFIG_SCHEMA({"auto_rearm_after": value})
                self.assertEqual(config["auto_rearm_after"].total_milliseconds, expected)

    def test_invalid_delays_are_rejected(self):
        # Do not let large durations silently truncate to the device's uint32_t.
        for value in ["-1s", "100us", "30d", "not-a-duration"]:
            with self.subTest(value=value):
                with self.assertRaises(cv.Invalid):
                    bridge.CONFIG_SCHEMA({"auto_rearm_after": value})


if __name__ == "__main__":
    unittest.main()
