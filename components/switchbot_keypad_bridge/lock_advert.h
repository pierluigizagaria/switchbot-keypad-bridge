#pragma once

// SwitchBot physical lock identification and battery extraction from BLE advertisements.

#include <cstddef>
#include <cstdint>

#include "physical_lock.h"

namespace esphome {
namespace switchbot_keypad_bridge {

bool is_lock_ultra_max_advert(const uint8_t *service_data, size_t service_len);

// `manufacturer_payload` is the SwitchBot manufacturer payload after the
// 2-byte company id (0x0969). Returns -1 when the advert does not carry a
// battery field for the supplied model.
int parse_lock_battery(PhysicalLockModel model,
                       const uint8_t *service_data, size_t service_len,
                       const uint8_t *manufacturer_payload,
                       size_t manufacturer_len);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
