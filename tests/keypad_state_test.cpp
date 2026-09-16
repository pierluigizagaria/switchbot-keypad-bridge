#include <cassert>
#include <cstdint>

#include "components/switchbot_keypad_bridge/keypad_state.h"

using esphome::switchbot_keypad_bridge::KeypadState;
using LockState = KeypadState::LockState;

int main() {
  // Existing installations remain unlocked until explicitly rearmed.
  KeypadState manual;
  assert(static_cast<uint8_t>(manual.lock_state()) == 0x81);
  manual.unlock(100);
  assert(static_cast<uint8_t>(manual.lock_state()) == 0x91);
  assert(!manual.update(20100));
  assert(!manual.update(UINT32_MAX));
  assert(manual.lock_state() == LockState::UNLOCKED);
  manual.rearm();
  manual.rearm();  // Safe to call repeatedly from a sensor or button.
  assert(manual.lock_state() == LockState::LOCKED);

  // No early expiry; one transition at the requested delay.
  KeypadState timed;
  timed.set_auto_rearm_after(20000);
  timed.unlock(100);
  assert(!timed.update(20099));
  assert(timed.lock_state() == LockState::UNLOCKED);
  assert(timed.update(20100));
  assert(timed.lock_state() == LockState::LOCKED);
  assert(!timed.update(20101));

  // A second unlock replaces the previous deadline.
  timed.unlock(30000);
  timed.unlock(49000);
  assert(!timed.update(50000));
  assert(!timed.update(68999));
  assert(timed.update(69000));

  // Explicit rearm, keypad Lock and pairing reset all cancel the timer.
  timed.unlock(70000);
  timed.rearm();
  assert(!timed.update(80000));
  timed.unlock(85000);
  assert(!timed.update(90000));
  assert(timed.lock_state() == LockState::UNLOCKED);
  assert(timed.update(105000));

  // Millisecond counter wrap must neither rearm early nor lose the timer.
  timed.unlock(UINT32_MAX - 9999);
  assert(!timed.update(UINT32_MAX));
  assert(!timed.update(9999));
  assert(timed.update(10000));

  // Configurable delays, including an explicit zero (disabled).
  KeypadState custom;
  custom.set_auto_rearm_after(1234);
  custom.unlock(0);
  assert(!custom.update(1233));
  assert(custom.update(1234));
  custom.set_auto_rearm_after(0);
  custom.unlock(1500);
  assert(!custom.update(100000));
  assert(custom.lock_state() == LockState::UNLOCKED);
  return 0;
}
