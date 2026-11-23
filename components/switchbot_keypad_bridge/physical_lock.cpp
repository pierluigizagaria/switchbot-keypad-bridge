#include "physical_lock.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#if __has_include("esphome/core/alloc_helpers.h") // Check if alloc_helpers.h is available
#include "esphome/core/alloc_helpers.h"
#endif
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "aes_ctr.h"
#include "ble_utils.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.lock";

constexpr uint8_t PROTOCOL_MAGIC = 0x57;
constexpr size_t WIRE_HEADER_LEN = 4;

struct NotifyWaiter {
  SemaphoreHandle_t sem{nullptr};
  std::string value;
};

bool wait_notify(NotifyWaiter &waiter, uint32_t timeout_ms, std::string &out) {
  if (xSemaphoreTake(waiter.sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
    return false;
  }
  out = waiter.value;
  return true;
}

// Rebuild a connectable address from the bare MAC the cloud stores. The BLE
// spec fixes the two most significant bits of a static random address to 11;
// anything else (like SwitchBot's public B0:E9:FE OUI) is a public address.
// A wrong guess only costs the discovery-scan fallback in connect_().
NimBLEAddress address_from_mac(const std::string &mac_pretty) {
  const std::string mac = upper_mac(mac_pretty);
  const uint8_t msb =
      static_cast<uint8_t>(std::strtol(mac.substr(0, 2).c_str(), nullptr, 16));
  const uint8_t type = ((msb & 0xC0) == 0xC0) ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
  return NimBLEAddress(mac, type);
}

NimBLEAddress discover_target(const std::string &mac_pretty, uint32_t timeout_ms) {
  NimBLEScan *scan = NimBLEDevice::getScan();
  configure_switchbot_scan(scan);
  const std::string target = upper_mac(mac_pretty);

  NimBLEScanResults results = scan->getResults(timeout_ms, false);
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice *adv = results.getDevice(i);
    if (upper_mac(adv->getAddress().toString()) == target) {
      ESP_LOGI(TAG, "Found lock %s (addr_type=%d, rssi=%d)",
               mac_pretty.c_str(), adv->getAddressType(), adv->getRSSI());
      return adv->getAddress();
    }
  }
  return NimBLEAddress{};
}

const uint8_t *lock_info_plaintext(PhysicalLockModel model, size_t &len) {
  static constexpr uint8_t ORIGINAL[] = {0x0F, 0x4F, 0x81, 0x01};
  static constexpr uint8_t PRO[]      = {0x0F, 0x4F, 0x81, 0x04};
  static constexpr uint8_t ULTRA[]    = {0x0F, 0x4F, 0x81, 0x07};
  static constexpr uint8_t VISION[]   = {0x0F, 0x4F, 0x81, 0x02};
  static constexpr uint8_t PRO_WIFI[] = {0x0F, 0x4F, 0x81, 0x0A};

  switch (model) {
    case PhysicalLockModel::LOCK:
    case PhysicalLockModel::LOCK_LITE:
      len = sizeof(ORIGINAL);
      return ORIGINAL;
    case PhysicalLockModel::LOCK_PRO:
      len = sizeof(PRO);
      return PRO;
    case PhysicalLockModel::LOCK_ULTRA:
      len = sizeof(ULTRA);
      return ULTRA;
    case PhysicalLockModel::LOCK_VISION:
    case PhysicalLockModel::LOCK_VISION_PRO:
      len = sizeof(VISION);
      return VISION;
    case PhysicalLockModel::LOCK_PRO_WIFI:
      len = sizeof(PRO_WIFI);
      return PRO_WIFI;
    default:
      len = 0;
      return nullptr;
  }
}

uint8_t normalize_mode_byte(uint8_t mode_byte) {
  // pySwitchbot treats 0 as CTR and 1 as GCM. Some captures use non-zero
  // feature bits around the low mode bit; keep this tolerant.
  return mode_byte & 0x01;
}

void increment_gcm_iv(std::array<uint8_t, 12> &iv) {
  for (int i = static_cast<int>(iv.size()) - 1; i >= 0; --i) {
    if (++iv[static_cast<size_t>(i)] != 0) break;
  }
}

}  // namespace

const char *physical_lock_model_str(PhysicalLockModel model) {
  switch (model) {
    case PhysicalLockModel::LOCK:
      return "lock";
    case PhysicalLockModel::LOCK_LITE:
      return "lock_lite";
    case PhysicalLockModel::LOCK_PRO:
      return "lock_pro";
    case PhysicalLockModel::LOCK_ULTRA:
      return "lock_ultra";
    case PhysicalLockModel::LOCK_VISION:
      return "lock_vision";
    case PhysicalLockModel::LOCK_VISION_PRO:
      return "lock_vision_pro";
    case PhysicalLockModel::LOCK_PRO_WIFI:
      return "lock_pro_wifi";
    default:
      return "unknown";
  }
}

PhysicalLockModel physical_lock_model_from_api_type(const std::string &device_type) {
  if (device_type == "WoLock") return PhysicalLockModel::LOCK;
  if (device_type == "WoLockLite") return PhysicalLockModel::LOCK_LITE;
  if (device_type == "WoLockPro") return PhysicalLockModel::LOCK_PRO;
  if (device_type == "W1091000") return PhysicalLockModel::LOCK_ULTRA;
  if (device_type == "W1141000") return PhysicalLockModel::LOCK_VISION;
  if (device_type == "W1141001") return PhysicalLockModel::LOCK_VISION_PRO;
  if (device_type == "W1114000") return PhysicalLockModel::LOCK_PRO_WIFI;
  return PhysicalLockModel::UNKNOWN;
}

bool is_supported_physical_lock_type(const std::string &device_type) {
  return physical_lock_model_from_api_type(device_type) != PhysicalLockModel::UNKNOWN;
}

bool lock_status_byte_plausible(PhysicalLockModel model, uint8_t state) {
  switch (model) {
    case PhysicalLockModel::LOCK:
    case PhysicalLockModel::LOCK_LITE:
    case PhysicalLockModel::LOCK_VISION:
    case PhysicalLockModel::LOCK_VISION_PRO:
      return ((state & 0x70) >> 4) <= 6;
    case PhysicalLockModel::LOCK_PRO:
    case PhysicalLockModel::LOCK_ULTRA:
    case PhysicalLockModel::LOCK_PRO_WIFI:
      return ((state & 0x78) >> 3) <= 6;
    default:
      return false;
  }
}

bool lock_info_response_plausible(PhysicalLockModel model,
                                  const std::vector<uint8_t> &response) {
  if (response.empty()) {
    return false;
  }

  // Keypad-side state poll replies have a stable 14-byte shape in captures:
  // <state> 08 <rolling> 41 00 00 00 00 80 <ctx0> <ctx1> 00 00 00.
  if (response.size() == 14 && response[1] == 0x08 && response[3] == 0x41 &&
      response[8] == 0x80) {
    return lock_status_byte_plausible(PhysicalLockModel::LOCK, response[0]);
  }

  // App-style lock-info replies are model-dependent. For example, a Lock
  // Ultra answering 0F 4F 81 07 returns a 16-byte payload such as
  // B2 00 26 00 81 00 0B F8 ...; pySwitchbot treats the encrypted wire-status
  // byte as the command result and parses this decrypted payload as lock data.
  return response.size() >= 6 && lock_status_byte_plausible(model, response[0]);
}

bool PhysicalLockClient::verify(const Config &config, std::string &error_out,
                                const ProgressCallback &progress) {
  size_t len = 0;
  const uint8_t *cmd = lock_info_plaintext(config.model, len);
  if (cmd == nullptr || len == 0) {
    error_out = "Unsupported SwitchBot Lock model.";
    return false;
  }
  std::vector<uint8_t> response;
  if (!this->send_plaintext(config, cmd, len, response, error_out, progress)) {
    return false;
  }
  if (response.empty()) {
    error_out = "Shared key verified but no lock-info payload was returned.";
    return false;
  }
  if (!lock_info_response_plausible(config.model, response)) {
    error_out = "The lock answered, but the shared-key lock-info payload was not valid.";
    return false;
  }
  return true;
}

bool PhysicalLockClient::send_plaintext(const Config &config, const uint8_t *plaintext,
                                        size_t plaintext_len,
                                        std::vector<uint8_t> &response_plaintext,
                                        std::string &error_out,
                                        const ProgressCallback &progress,
                                        const ResponseCallback &response_callback) {
  response_plaintext.clear();
  if (plaintext == nullptr || plaintext_len == 0) {
    error_out = "Empty lock command.";
    return false;
  }

  std::vector<std::vector<uint8_t>> commands = {
      std::vector<uint8_t>(plaintext, plaintext + plaintext_len)};
  std::vector<std::vector<uint8_t>> responses;
  if (!this->send_plaintext_sequence(config, commands, responses, error_out,
                                     progress, response_callback)) {
    return false;
  }
  if (!responses.empty()) {
    response_plaintext = std::move(responses.front());
  }
  return true;
}

bool PhysicalLockClient::send_plaintext_sequence(
    const Config &config,
    const std::vector<std::vector<uint8_t>> &commands,
    std::vector<std::vector<uint8_t>> &responses,
    std::string &error_out,
    const ProgressCallback &progress,
    const ResponseCallback &response_callback) {
  responses.clear();
  if (commands.empty()) {
    error_out = "Empty lock command sequence.";
    return false;
  }
  for (const auto &cmd : commands) {
    if (cmd.empty()) {
      error_out = "Empty lock command in sequence.";
      return false;
    }
  }

  NimBLEClient *client = nullptr;
  NimBLERemoteCharacteristic *rx = nullptr;
  NimBLERemoteCharacteristic *tx = nullptr;
  if (!this->connect_(config, client, rx, tx, error_out, progress)) {
    return false;
  }

  NotifyWaiter waiter;
  waiter.sem = xSemaphoreCreateBinary();
  if (waiter.sem == nullptr) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    error_out = "Could not allocate lock notification semaphore.";
    return false;
  }

  if (!tx->subscribe(true,
                     [&waiter](NimBLERemoteCharacteristic *, uint8_t *data,
                               size_t length, bool /*is_notify*/) {
                       waiter.value.assign(reinterpret_cast<const char *>(data), length);
                       xSemaphoreGive(waiter.sem);
                     })) {
    vSemaphoreDelete(waiter.sem);
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    error_out = "Could not subscribe to lock notifications.";
    return false;
  }

  bool ok = false;
  Session session;
  std::string notify;
  if (progress) progress(Phase::SESSION);
  uint8_t iv_req[8] = {PROTOCOL_MAGIC, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03, config.key_id};
  if (!rx->writeValue(iv_req, sizeof(iv_req), /*response=*/true)) {
    error_out = "Could not request a lock encryption session.";
  } else if (!wait_notify(waiter, 3000, notify)) {
    error_out = "Lock did not open an encryption session.";
  } else if (this->parse_session_response_(notify, session, error_out)) {
    ok = true;
    for (const auto &cmd : commands) {
      if (progress) progress(Phase::COMMAND);
      if (!this->send_encrypted_(config, session, rx, cmd.data(), cmd.size(), error_out)) {
        ok = false;
        break;
      }
      if (!wait_notify(waiter, 2500, notify)) {
        error_out = "Lock did not answer the forwarded command.";
        ok = false;
        break;
      } else {
        std::vector<uint8_t> response;
        ok = this->decrypt_notify_(config, session, notify, response, error_out);
        if (!ok) {
          break;
        }
        if (response_callback) {
          response_callback(response);
        }
        responses.push_back(std::move(response));
      }
    }
  }

  tx->unsubscribe();
  vSemaphoreDelete(waiter.sem);
  client->disconnect();
  NimBLEDevice::deleteClient(client);
  return ok;
}

bool PhysicalLockClient::provision_and_verify_shared_key(
    const Config &provisioning_config,
    const std::vector<std::vector<uint8_t>> &provision_commands,
    std::vector<std::vector<uint8_t>> &provision_responses,
    const Config &shared_config,
    std::string &error_out,
    const ProgressCallback &provision_progress,
    const CommandProgressCallback &provision_command_progress,
    const ProgressCallback &verify_progress) {
  provision_responses.clear();
  if (provision_commands.empty()) {
    error_out = "Empty lock provisioning command sequence.";
    return false;
  }
  for (const auto &cmd : provision_commands) {
    if (cmd.empty()) {
      error_out = "Empty lock provisioning command.";
      return false;
    }
  }

  size_t verify_len = 0;
  const uint8_t *verify_cmd = lock_info_plaintext(shared_config.model, verify_len);
  if (verify_cmd == nullptr || verify_len == 0) {
    error_out = "Unsupported SwitchBot Lock model.";
    return false;
  }

  NimBLEClient *client = nullptr;
  NimBLERemoteCharacteristic *rx = nullptr;
  NimBLERemoteCharacteristic *tx = nullptr;
  if (!this->connect_(provisioning_config, client, rx, tx, error_out,
                      provision_progress)) {
    return false;
  }

  NotifyWaiter waiter;
  waiter.sem = xSemaphoreCreateBinary();
  if (waiter.sem == nullptr) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    error_out = "Could not allocate lock notification semaphore.";
    return false;
  }

  if (!tx->subscribe(true,
                     [&waiter](NimBLERemoteCharacteristic *, uint8_t *data,
                               size_t length, bool /*is_notify*/) {
                       waiter.value.assign(reinterpret_cast<const char *>(data), length);
                       xSemaphoreGive(waiter.sem);
                     })) {
    vSemaphoreDelete(waiter.sem);
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    error_out = "Could not subscribe to lock notifications.";
    return false;
  }

  auto run_session =
      [&](const Config &config, const char *session_name,
          const std::vector<std::vector<uint8_t>> &commands,
          std::vector<std::vector<uint8_t>> &responses,
          const ProgressCallback &progress,
          const CommandProgressCallback &command_progress) -> bool {
    responses.clear();
    Session session;
    std::string notify;
    if (progress) progress(Phase::SESSION);
    uint8_t iv_req[8] = {PROTOCOL_MAGIC, 0x00, 0x00, 0x00,
                         0x0F, 0x21, 0x03, config.key_id};
    if (!rx->writeValue(iv_req, sizeof(iv_req), /*response=*/true)) {
      error_out = std::string("Could not request a ") + session_name +
                  " encryption session.";
      return false;
    }
    if (!wait_notify(waiter, 3000, notify)) {
      error_out = std::string("Lock did not open the ") + session_name +
                  " encryption session.";
      return false;
    }
    if (!this->parse_session_response_(notify, session, error_out)) {
      return false;
    }

    for (size_t i = 0; i < commands.size(); ++i) {
      const auto &cmd = commands[i];
      if (command_progress) {
        command_progress(i);
      } else if (progress) {
        progress(Phase::COMMAND);
      }
      if (!this->send_encrypted_(config, session, rx, cmd.data(), cmd.size(),
                                 error_out)) {
        return false;
      }
      if (!wait_notify(waiter, 2500, notify)) {
        error_out = "Lock did not answer the forwarded command.";
        return false;
      }
      std::vector<uint8_t> response;
      if (!this->decrypt_notify_(config, session, notify, response, error_out)) {
        return false;
      }
      responses.push_back(std::move(response));
    }
    return true;
  };

  bool ok = run_session(provisioning_config, "lock provisioning",
                        provision_commands, provision_responses,
                        provision_progress, provision_command_progress);
  if (ok) {
    std::vector<std::vector<uint8_t>> verify_commands = {
        std::vector<uint8_t>(verify_cmd, verify_cmd + verify_len)};
    std::vector<std::vector<uint8_t>> verify_responses;
    ok = run_session(shared_config, "shared-key verification",
                     verify_commands, verify_responses,
                     verify_progress, nullptr);
    if (ok) {
      if (verify_responses.empty() || verify_responses.front().empty()) {
        error_out = "Shared key verified but no lock-info payload was returned.";
        ok = false;
      } else if (!lock_info_response_plausible(shared_config.model,
                                               verify_responses.front())) {
        error_out = "The lock answered, but the shared-key lock-info payload was not valid.";
        ok = false;
      }
    }
  }

  tx->unsubscribe();
  vSemaphoreDelete(waiter.sem);
  client->disconnect();
  NimBLEDevice::deleteClient(client);
  return ok;
}

bool PhysicalLockClient::connect_(const Config &config, NimBLEClient *&client,
                                  NimBLERemoteCharacteristic *&rx,
                                  NimBLERemoteCharacteristic *&tx,
                                  std::string &error_out,
                                  const ProgressCallback &progress) {
  // Two attempts at most: the first connects straight to the last cached
  // advertisement address — or, fresh after boot, to the address rebuilt
  // from the stored MAC — skipping the ~2.5 s discovery scan entirely. Only
  // if that direct connect fails does the second attempt fall back to a scan.
  for (int attempt = 0; attempt < 2; ++attempt) {
    NimBLEAddress target;
    if (attempt == 0) {
      const bool cache_ok =
          !this->cached_mac_.empty() && this->cached_mac_ == config.mac;
      target = cache_ok ? this->cached_addr_ : address_from_mac(config.mac);
    } else {
      if (progress) progress(Phase::SCAN);
      target = discover_target(config.mac, 2500);
      if (target.isNull()) {
        error_out = "Could not see the lock over BLE. Keep it near the bridge and retry.";
        return false;
      }
    }

    if (progress) progress(Phase::CONNECT);
    SwitchbotGattConnection conn;
    if (!connect_switchbot_service(target, 5000, "physical lock", conn, error_out)) {
      if (attempt == 0) {
        this->cached_mac_.clear();  // direct connect failed — scan for real
        continue;
      }
      return false;
    }

    if (progress) progress(Phase::DISCOVER);
    client = conn.client;
    rx = conn.rx;
    tx = conn.tx;
    this->cached_addr_ = target;
    this->cached_mac_  = config.mac;
    return true;
  }
  error_out = "Could not connect to the physical lock.";
  return false;
}

bool PhysicalLockClient::parse_session_response_(const std::string &wire,
                                                 Session &session,
                                                 std::string &error_out) {
  if (wire.size() < WIRE_HEADER_LEN || static_cast<uint8_t>(wire[0]) != 0x01) {
    error_out = "Lock returned a malformed encryption-session response.";
    return false;
  }
  const uint8_t *data = reinterpret_cast<const uint8_t *>(wire.data());
  const uint8_t mode = normalize_mode_byte(data[2]);
  if (mode == 1) {
    if (wire.size() < 20) {
      error_out = "Lock returned a short AES-GCM IV.";
      return false;
    }
    session.mode = CryptoMode::GCM;
    std::memcpy(session.gcm_iv.data(), data + WIRE_HEADER_LEN, session.gcm_iv.size());
    ESP_LOGD(TAG, "Lock encryption session: AES-GCM");
    return true;
  }
  if (wire.size() < WIRE_HEADER_LEN + session.ctr_iv.size()) {
    error_out = "Lock returned a short AES-CTR IV.";
    return false;
  }
  session.mode = CryptoMode::CTR;
  std::memcpy(session.ctr_iv.data(), data + WIRE_HEADER_LEN, session.ctr_iv.size());
  ESP_LOGD(TAG, "Lock encryption session: AES-CTR");
  return true;
}

bool PhysicalLockClient::send_encrypted_(const Config &config, const Session &session,
                                         NimBLERemoteCharacteristic *rx,
                                         const uint8_t *plaintext,
                                         size_t plaintext_len,
                                         std::string &error_out) {
  std::vector<uint8_t> frame(WIRE_HEADER_LEN + plaintext_len);
  frame[0] = PROTOCOL_MAGIC;
  frame[1] = config.key_id;

  if (session.mode == CryptoMode::GCM) {
    uint8_t tag[16];
    if (!aes_gcm_encrypt_raw_key(config.key.data(), session.gcm_iv.data(),
                                 plaintext, frame.data() + WIRE_HEADER_LEN,
                                 plaintext_len, tag)) {
      error_out = "Could not encrypt lock command with AES-GCM.";
      return false;
    }
    frame[2] = tag[0];
    frame[3] = tag[1];
  } else {
    frame[2] = session.ctr_iv[0];
    frame[3] = session.ctr_iv[1];
    if (!aes_ctr_xcrypt_raw_key(config.key.data(), session.ctr_iv.data(),
                                plaintext, frame.data() + WIRE_HEADER_LEN,
                                plaintext_len)) {
      error_out = "Could not encrypt lock command with AES-CTR.";
      return false;
    }
  }

  ESP_LOGV(TAG, "TX lock %s",
           format_hex_pretty(frame.data(), frame.size()).c_str());
  if (!rx->writeValue(frame.data(), frame.size(), /*response=*/true)) {
    error_out = "Could not write encrypted command to the lock.";
    return false;
  }
  return true;
}

bool PhysicalLockClient::decrypt_notify_(const Config &config, const Session &session,
                                         const std::string &wire,
                                         std::vector<uint8_t> &out,
                                         std::string &error_out) {
  if (wire.size() < WIRE_HEADER_LEN) {
    error_out = "Lock returned a malformed notification.";
    return false;
  }
  const uint8_t *data = reinterpret_cast<const uint8_t *>(wire.data());
  ESP_LOGV(TAG, "RX lock %s", format_hex_pretty(data, wire.size()).c_str());
  const size_t payload_len = wire.size() - WIRE_HEADER_LEN;
  out.resize(payload_len);
  if (payload_len == 0) {
    return true;
  }

  if (session.mode == CryptoMode::GCM) {
    std::array<uint8_t, 12> iv = session.gcm_iv;
    increment_gcm_iv(iv);
    if (!aes_gcm_decrypt_raw_key(config.key.data(), iv.data(),
                                 data + WIRE_HEADER_LEN, out.data(), payload_len)) {
      error_out = "Could not decrypt lock response with AES-GCM.";
      return false;
    }
  } else {
    if (!aes_ctr_xcrypt_raw_key(config.key.data(), session.ctr_iv.data(),
                                data + WIRE_HEADER_LEN, out.data(), payload_len)) {
      error_out = "Could not decrypt lock response with AES-CTR.";
      return false;
    }
  }
  ESP_LOGV(TAG, "RX lock plaintext %s",
           format_hex_pretty(out.data(), out.size()).c_str());
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
