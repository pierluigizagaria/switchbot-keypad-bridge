#include "lock_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

int valid_percent(uint8_t raw) {
  const int value = raw & 0x7F;
  return value <= 100 ? value : -1;
}

bool is_ultra_max_product_id(const uint8_t *data) {
  return (data[0] == 0x00 || data[0] == 0x01) &&
         data[1] == 0x11 && data[2] == 0x9F && data[3] == 0xB8;
}

}  // namespace

bool is_lock_ultra_max_advert(const uint8_t *service_data, size_t service_len) {
  if (service_data == nullptr || service_len <= 5) return false;
  // Match the product ID with or without the optional trailing byte, as in pySwitchbot.
  return is_ultra_max_product_id(service_data + service_len - 4) ||
         is_ultra_max_product_id(service_data + service_len - 5);
}

int parse_lock_battery(PhysicalLockModel model,
                       const uint8_t *service_data, size_t service_len,
                       const uint8_t *manufacturer_payload,
                       size_t manufacturer_len) {
  switch (model) {
    case PhysicalLockModel::LOCK:
    case PhysicalLockModel::LOCK_LITE:
    case PhysicalLockModel::LOCK_VISION:
      if (service_data == nullptr || service_len < 3) return -1;
      return valid_percent(service_data[2]);

    case PhysicalLockModel::LOCK_PRO:
    case PhysicalLockModel::LOCK_PRO_WIFI:
    case PhysicalLockModel::LOCK_ULTRA:
    case PhysicalLockModel::LOCK_ULTRA_MAX:
    case PhysicalLockModel::LOCK_VISION_PRO:
      if (manufacturer_payload == nullptr || manufacturer_len < 10) return -1;
      return valid_percent(manufacturer_payload[9]);

    default:
      return -1;
  }
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
