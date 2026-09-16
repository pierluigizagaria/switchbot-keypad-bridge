#pragma once

#include <cstdint>

namespace esphome {
namespace switchbot_keypad_bridge {

// State of the emulated lock, not feedback from a physical lock. Kept apart
// from the BLE session so a reconnect cannot cancel a pending rearm.
// All methods are called on the ESPHome main task.
class KeypadState {
 public:
  enum class LockState : uint8_t { LOCKED = 0x81, UNLOCKED = 0x91 };

  void set_auto_rearm_after(uint32_t ms) { this->auto_rearm_after_ms_ = ms; }
  uint32_t auto_rearm_after() const { return this->auto_rearm_after_ms_; }
  LockState lock_state() const { return this->lock_state_; }

  // Used by explicit rearm, keypad Lock, and pairing reset. Does not emit
  // events or send commands to a linked physical lock.
  void rearm() {
    this->lock_state_ = LockState::LOCKED;
    this->rearm_pending_ = false;
  }

  void unlock(uint32_t now) {
    this->lock_state_ = LockState::UNLOCKED;
    this->unlocked_at_ = now;
    this->rearm_pending_ = this->auto_rearm_after_ms_ != 0;
  }

  // Unsigned elapsed time remains correct across millis() rollover.
  // Returns true once per expiry, for logging by the bridge.
  bool update(uint32_t now) {
    if (!this->rearm_pending_ || this->auto_rearm_after_ms_ == 0 ||
        static_cast<uint32_t>(now - this->unlocked_at_) < this->auto_rearm_after_ms_) {
      return false;
    }
    this->rearm();
    return true;
  }

 protected:
  LockState lock_state_{LockState::LOCKED};
  uint32_t auto_rearm_after_ms_{0};
  uint32_t unlocked_at_{0};
  bool rearm_pending_{false};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
