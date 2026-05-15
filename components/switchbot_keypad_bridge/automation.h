#pragma once

#include "esphome/core/automation.h"
#include "switchbot_keypad_bridge.h"

namespace esphome {
namespace switchbot_keypad_bridge {

class LockTrigger : public Trigger<> {
 public:
  explicit LockTrigger(SwitchbotKeypadBridge *parent) {
    parent->add_on_lock_callback([this]() { this->trigger(); });
  }
};

class UnlockTrigger : public Trigger<std::string, int> {
 public:
  explicit UnlockTrigger(SwitchbotKeypadBridge *parent) {
    parent->add_on_unlock_callback(
        [this](const std::string &method, int index) { this->trigger(method, index); });
  }
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
