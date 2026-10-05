#include "ble_utils.h"

#include "esphome/core/hal.h"
#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

std::vector<uint8_t> switchbot_manufacturer_payload(const NimBLEAdvertisedDevice *adv) {
  if (!adv->haveManufacturerData()) {
    return {};
  }
  const std::string mfr = adv->getManufacturerData();
  if (mfr.size() < 2) {
    return {};
  }
  const auto *data = reinterpret_cast<const uint8_t *>(mfr.data());
  if (data[0] != 0x69 || data[1] != 0x09) {
    return {};
  }
  return std::vector<uint8_t>(data + 2, data + mfr.size());
}

std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr) {
  std::array<uint8_t, 6> out{};
  const uint8_t *raw = addr.getBase()->val;  // little-endian
  for (size_t i = 0; i < 6; ++i) {
    out[i] = raw[5 - i];
  }
  return out;
}

void configure_switchbot_scan(NimBLEScan *scan) {
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);
}

namespace {
const char *const BLE_TAG = "switchbot_keypad_bridge.ble";
}  // namespace

NimBLEClient *connect_switchbot_link(const NimBLEAddress &target, uint32_t timeout_ms,
                                     const char *device_label, std::string &error_out) {
  NimBLEClient *client = NimBLEDevice::createClient();
  if (client == nullptr) {
    error_out = "Could not allocate a BLE client for the ";
    error_out += device_label;
    error_out += ".";
    return nullptr;
  }

  client->setConnectTimeout(timeout_ms);
  // Ask for a 10-20 ms connection interval (1.25 ms units) instead of
  // NimBLE's 30-50 ms default. Every GATT round trip (discovery, subscribe,
  // session, command) costs at least one interval, so this dominates relay
  // latency. Kept above 7.5 ms so the keypad's peripheral link still gets
  // radio time. Supervision timeout 3 s (10 ms units).
  client->setConnectionParams(8, 16, 0, 300);
  const uint32_t t0 = esphome::millis();
  if (!client->connect(target)) {
    NimBLEDevice::deleteClient(client);
    error_out = "Could not connect to the ";
    error_out += device_label;
    error_out += ".";
    return nullptr;
  }

  const NimBLEConnInfo info = client->getConnInfo();
  ESP_LOGD(BLE_TAG, "%s: link up in %ums (interval %.2fms, latency %u)", device_label,
           static_cast<unsigned>(esphome::millis() - t0), info.getConnInterval() * 1.25f,
           static_cast<unsigned>(info.getConnLatency()));
  return client;
}

bool discover_switchbot_service(NimBLEClient *client, const char *device_label,
                                SwitchbotGattConnection &conn, std::string &error_out) {
  const uint32_t t0 = esphome::millis();
  conn = SwitchbotGattConnection{};
  conn.client = client;
  NimBLERemoteService *svc = client->getService(NimBLEUUID(SWITCHBOT_SERVICE_UUID));
  if (svc != nullptr) {
    conn.rx = svc->getCharacteristic(NimBLEUUID(SWITCHBOT_RX_CHAR_UUID));
    conn.tx = svc->getCharacteristic(NimBLEUUID(SWITCHBOT_TX_CHAR_UUID));
  }
  if (conn.rx == nullptr || conn.tx == nullptr) {
    conn.rx = nullptr;
    conn.tx = nullptr;
    error_out = "The ";
    error_out += device_label;
    error_out += " does not expose the SwitchBot GATT service.";
    return false;
  }
  ESP_LOGD(BLE_TAG, "%s: service discovery took %ums", device_label,
           static_cast<unsigned>(esphome::millis() - t0));
  return true;
}

bool connect_switchbot_service(const NimBLEAddress &target, uint32_t timeout_ms,
                               const char *device_label,
                               SwitchbotGattConnection &conn,
                               std::string &error_out) {
  conn = SwitchbotGattConnection{};
  NimBLEClient *client = connect_switchbot_link(target, timeout_ms, device_label, error_out);
  if (client == nullptr) {
    return false;
  }
  if (!discover_switchbot_service(client, device_label, conn, error_out)) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    conn = SwitchbotGattConnection{};
    return false;
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
