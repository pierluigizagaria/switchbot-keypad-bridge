#pragma once

// Small NimBLE helpers shared by the bridge, the pairer and the setup UI.
//
// keypad_advert.h and mac_utils.h are deliberately NimBLE-free; everything
// here is the glue between NimBLE types and that raw-bytes world
// (service-data extraction, address bytes, common scan parameters).

#include "nimble_compat.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

constexpr const char *SWITCHBOT_SERVICE_UUID = "cba20d00-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *SWITCHBOT_RX_CHAR_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *SWITCHBOT_TX_CHAR_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b";

struct SwitchbotGattConnection {
  NimBLEClient *client{nullptr};
  NimBLERemoteCharacteristic *rx{nullptr};
  NimBLERemoteCharacteristic *tx{nullptr};
};

// Read the SwitchBot service-data blob from an advertisement (UUID 0xFD3D,
// with the legacy 0x0D00 as a fallback). Empty when not present.
std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv);

// Read the SwitchBot manufacturer data after the 2-byte company id (0x0969).
// Empty when the advert has no SwitchBot manufacturer payload.
std::vector<uint8_t> switchbot_manufacturer_payload(const NimBLEAdvertisedDevice *adv);

// Address bytes in big-endian (printed) order — NimBLE stores them reversed.
std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr);

// Apply the scan parameters every SwitchBot scan in this project uses, and
// drop any previous results. Active scanning is required — the keypad's
// 0xFD3D service data rides in the scan response.
void configure_switchbot_scan(NimBLEScan *scan);

// Open a BLE link without any GATT discovery. Returns the connected client,
// or nullptr (client already freed) with `error_out` set.
NimBLEClient *connect_switchbot_link(const NimBLEAddress &target, uint32_t timeout_ms,
                                     const char *device_label, std::string &error_out);

// Discover the SwitchBot service and its RX/TX characteristics on an open
// link. Leaves the link open on failure; the caller disconnects.
bool discover_switchbot_service(NimBLEClient *client, const char *device_label,
                                SwitchbotGattConnection &conn, std::string &error_out);

// connect_switchbot_link() + discover_switchbot_service(); disconnects and
// frees the client on failure.
bool connect_switchbot_service(const NimBLEAddress &target, uint32_t timeout_ms,
                               const char *device_label,
                               SwitchbotGattConnection &conn,
                               std::string &error_out);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
