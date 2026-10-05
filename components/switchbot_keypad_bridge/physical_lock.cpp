#include "physical_lock.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include <memory>
#include <mutex>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <host/ble_gap.h>
#include <host/ble_gatt.h>
#include <host/ble_hs.h>

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

// Lock replies arrive as GATT notifications. Links driven by cached handles
// have no discovered characteristic to subscribe through, so every reply is
// taken from a global NimBLE GAP listener and routed to the one exchange in
// progress. Exchanges never overlap: one relay runs at a time, and the wizard
// refuses to link a lock while one is linked. The listener runs on the
// NimBLE host task.
struct ReplyRoute {
  std::mutex mu;
  bool active{false};
  uint16_t conn_handle{0};
  uint16_t attr_handle{0};
  SemaphoreHandle_t sem{nullptr};
  std::string value;
};
ReplyRoute g_reply_route;
struct ble_gap_event_listener g_reply_listener;

int on_gap_event(struct ble_gap_event *event, void * /*arg*/) {
  if (event->type != BLE_GAP_EVENT_NOTIFY_RX) {
    return 0;
  }
  std::lock_guard<std::mutex> lk(g_reply_route.mu);
  if (!g_reply_route.active ||
      event->notify_rx.conn_handle != g_reply_route.conn_handle ||
      event->notify_rx.attr_handle != g_reply_route.attr_handle) {
    return 0;
  }
  const uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
  g_reply_route.value.assign(len, '\0');
  if (len > 0) {
    os_mbuf_copydata(event->notify_rx.om, 0, len, &g_reply_route.value[0]);
  }
  xSemaphoreGive(g_reply_route.sem);
  return 0;
}

// Completion of one write-with-response. Shared with the NimBLE callback so
// a write that outlives its caller's timeout never touches freed memory.
struct WriteResult {
  SemaphoreHandle_t sem{nullptr};
  int status{BLE_HS_ETIMEOUT};
  ~WriteResult() {
    if (this->sem != nullptr) vSemaphoreDelete(this->sem);
  }
};

int on_write_done(uint16_t /*conn_handle*/, const struct ble_gatt_error *error,
                  struct ble_gatt_attr * /*attr*/, void *arg) {
  auto *ref = static_cast<std::shared_ptr<WriteResult> *>(arg);
  (*ref)->status = error != nullptr ? error->status : 0;
  xSemaphoreGive((*ref)->sem);
  delete ref;
  return 0;
}

// Write with response to a bare attribute handle. Returns 0 on success, else
// the NimBLE/ATT status (BLE_HS_ETIMEOUT when no answer arrived in time).
int write_handle(uint16_t conn_handle, uint16_t attr_handle, const uint8_t *data,
                 size_t length, uint32_t timeout_ms = 3000) {
  auto result = std::make_shared<WriteResult>();
  result->sem = xSemaphoreCreateBinary();
  if (result->sem == nullptr) {
    return BLE_HS_ENOMEM;
  }
  auto *ref = new std::shared_ptr<WriteResult>(result);
  const int rc = ble_gattc_write_flat(conn_handle, attr_handle, data,
                                      static_cast<uint16_t>(length), on_write_done, ref);
  if (rc != 0) {
    delete ref;
    return rc;
  }
  if (xSemaphoreTake(result->sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
    return BLE_HS_ETIMEOUT;
  }
  return result->status;
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

// RAII claim on the global reply route for one link.
class PhysicalLockClient::ReplyChannel {
 public:
  ReplyChannel(uint16_t conn_handle, uint16_t attr_handle) {
    std::lock_guard<std::mutex> lk(g_reply_route.mu);
    if (g_reply_route.active || g_reply_route.sem == nullptr) {
      return;
    }
    g_reply_route.active = true;
    g_reply_route.conn_handle = conn_handle;
    g_reply_route.attr_handle = attr_handle;
    g_reply_route.value.clear();
    xSemaphoreTake(g_reply_route.sem, 0);
    this->owner_ = true;
  }
  ~ReplyChannel() {
    if (this->owner_) {
      std::lock_guard<std::mutex> lk(g_reply_route.mu);
      g_reply_route.active = false;
    }
  }
  ReplyChannel(const ReplyChannel &) = delete;
  ReplyChannel &operator=(const ReplyChannel &) = delete;

  bool claimed() const { return this->owner_; }
  void retarget(uint16_t attr_handle) {
    std::lock_guard<std::mutex> lk(g_reply_route.mu);
    g_reply_route.attr_handle = attr_handle;
  }
  // Drop a reply that arrived before the next request was sent.
  void drain() { xSemaphoreTake(g_reply_route.sem, 0); }
  bool wait(uint32_t timeout_ms, std::string &out) {
    if (xSemaphoreTake(g_reply_route.sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
      return false;
    }
    std::lock_guard<std::mutex> lk(g_reply_route.mu);
    out = g_reply_route.value;
    return true;
  }

 private:
  bool owner_{false};
};

bool PhysicalLockClient::install_reply_listener() {
  if (g_reply_route.sem == nullptr) {
    g_reply_route.sem = xSemaphoreCreateBinary();
    if (g_reply_route.sem == nullptr) {
      return false;
    }
  }
  const int rc = ble_gap_event_listener_register(&g_reply_listener, on_gap_event, nullptr);
  if (rc != 0 && rc != BLE_HS_EALREADY) {
    ESP_LOGE(TAG, "Could not register the lock reply listener (rc=%d)", rc);
    return false;
  }
  return true;
}

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

PhysicalLockClient::PhysicalLockClient() = default;

PhysicalLockClient::~PhysicalLockClient() { this->close(); }

bool PhysicalLockClient::open(const Config &config, std::string &error_out,
                              const ProgressCallback &progress) {
  this->close();
  if (!this->connect_(config, this->held_link_, error_out, progress)) {
    return false;
  }
  this->held_replies_.reset(new ReplyChannel(this->held_link_.client->getConnHandle(),
                                             this->held_link_.handles.tx));
  if (!this->held_replies_->claimed()) {
    error_out = "Another lock exchange is already in progress.";
    this->close();
    return false;
  }
  if (progress) progress(Phase::SESSION);
  if (!this->open_session_with_fallback_(config, this->held_link_, *this->held_replies_,
                                         this->held_session_, error_out)) {
    this->close();
    return false;
  }
  this->held_config_ = config;
  this->held_open_ = true;
  return true;
}

bool PhysicalLockClient::send(const uint8_t *plaintext, size_t plaintext_len,
                              std::vector<uint8_t> &response_plaintext,
                              std::string &error_out) {
  response_plaintext.clear();
  if (!this->held_open_) {
    error_out = "Lock link is not open.";
    return false;
  }
  if (plaintext == nullptr || plaintext_len == 0) {
    error_out = "Empty lock command.";
    return false;
  }
  const std::vector<uint8_t> command(plaintext, plaintext + plaintext_len);
  return this->exchange_(this->held_config_, this->held_session_, this->held_link_,
                         *this->held_replies_, command, response_plaintext, error_out);
}

void PhysicalLockClient::close() {
  // Release the reply route before the link goes away.
  this->held_replies_.reset();
  this->close_(this->held_link_);
  this->held_session_ = Session{};
  this->held_open_ = false;
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

  if (!this->open(config, error_out, progress)) {
    return false;
  }
  bool ok = true;
  for (const auto &cmd : commands) {
    if (progress) progress(Phase::COMMAND);
    std::vector<uint8_t> response;
    if (!this->send(cmd.data(), cmd.size(), response, error_out)) {
      ok = false;
      break;
    }
    if (response_callback) {
      response_callback(response);
    }
    responses.push_back(std::move(response));
  }
  this->close();
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

  Link link;
  if (!this->connect_(provisioning_config, link, error_out, provision_progress)) {
    return false;
  }

  bool ok = false;
  {
    ReplyChannel replies(link.client->getConnHandle(), link.handles.tx);
    if (!replies.claimed()) {
      error_out = "Another lock exchange is already in progress.";
    } else {
      auto run_session =
          [&](const Config &config, const char *session_name,
              const std::vector<std::vector<uint8_t>> &commands,
              std::vector<std::vector<uint8_t>> &responses,
              const ProgressCallback &progress,
              const CommandProgressCallback &command_progress) -> bool {
        responses.clear();
        Session session;
        if (progress) progress(Phase::SESSION);
        if (!this->open_session_with_fallback_(config, link, replies, session, error_out)) {
          error_out = std::string(session_name) + ": " + error_out;
          return false;
        }
        for (size_t i = 0; i < commands.size(); ++i) {
          if (command_progress) {
            command_progress(i);
          } else if (progress) {
            progress(Phase::COMMAND);
          }
          std::vector<uint8_t> response;
          if (!this->exchange_(config, session, link, replies, commands[i], response,
                               error_out)) {
            return false;
          }
          responses.push_back(std::move(response));
        }
        return true;
      };

      ok = run_session(provisioning_config, "Lock provisioning", provision_commands,
                       provision_responses, provision_progress,
                       provision_command_progress);
      if (ok) {
        std::vector<std::vector<uint8_t>> verify_commands = {
            std::vector<uint8_t>(verify_cmd, verify_cmd + verify_len)};
        std::vector<std::vector<uint8_t>> verify_responses;
        ok = run_session(shared_config, "Shared-key verification", verify_commands,
                         verify_responses, verify_progress, nullptr);
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
    }
  }

  this->close_(link);
  return ok;
}

bool PhysicalLockClient::connect_(const Config &config, Link &link,
                                  std::string &error_out,
                                  const ProgressCallback &progress) {
  link = Link{};
  // Cached handles belong to the lock they were discovered on.
  if (this->cached_mac_ != config.mac) {
    this->cached_handles_ = GattHandles{};
  }

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
    link.client = connect_switchbot_link(target, 5000, "physical lock", error_out);
    if (link.client == nullptr) {
      if (attempt == 0) {
        this->cached_mac_.clear();  // direct connect failed — scan for real
        continue;
      }
      return false;
    }
    this->cached_addr_ = target;
    this->cached_mac_  = config.mac;

    if (this->cached_handles_.valid()) {
      link.handles = this->cached_handles_;
      link.from_cache = true;
      ESP_LOGD(TAG, "Using cached lock handles (rx=0x%04X tx=0x%04X cccd=0x%04X)",
               link.handles.rx, link.handles.tx, link.handles.cccd);
    } else if (!this->discover_handles_(link, error_out)) {
      this->close_(link);
      return false;
    }
    if (progress) progress(Phase::DISCOVER);
    return true;
  }
  error_out = "Could not connect to the physical lock.";
  return false;
}

bool PhysicalLockClient::discover_handles_(Link &link, std::string &error_out) {
  SwitchbotGattConnection conn;
  if (!discover_switchbot_service(link.client, "physical lock", conn, error_out)) {
    return false;
  }
  NimBLERemoteDescriptor *cccd =
      conn.tx->getDescriptor(NimBLEUUID(static_cast<uint16_t>(0x2902)));
  if (cccd == nullptr) {
    error_out = "The lock's reply characteristic cannot send notifications.";
    return false;
  }
  link.handles.rx = conn.rx->getHandle();
  link.handles.tx = conn.tx->getHandle();
  link.handles.cccd = cccd->getHandle();
  link.from_cache = false;
  this->cached_handles_ = link.handles;
  ESP_LOGD(TAG, "Discovered lock handles (rx=0x%04X tx=0x%04X cccd=0x%04X)",
           link.handles.rx, link.handles.tx, link.handles.cccd);
  return true;
}

bool PhysicalLockClient::open_session_(const Config &config, const Link &link,
                                       ReplyChannel &replies, Session &session,
                                       std::string &error_out) {
  const uint16_t conn_handle = link.client->getConnHandle();
  static constexpr uint8_t ENABLE_NOTIFY[2] = {0x01, 0x00};
  int rc = write_handle(conn_handle, link.handles.cccd, ENABLE_NOTIFY, sizeof(ENABLE_NOTIFY));
  if (rc != 0) {
    error_out = "Could not enable lock notifications (rc=" + std::to_string(rc) + ").";
    return false;
  }

  replies.drain();
  const uint8_t iv_req[8] = {PROTOCOL_MAGIC, 0x00, 0x00, 0x00,
                             0x0F, 0x21, 0x03, config.key_id};
  rc = write_handle(conn_handle, link.handles.rx, iv_req, sizeof(iv_req));
  if (rc != 0) {
    error_out = "Could not request a lock encryption session (rc=" +
                std::to_string(rc) + ").";
    return false;
  }

  // The lock answers in ~0.1 s. On cached handles, give up sooner so a stale
  // cache falls back to discovery without a long stall.
  std::string notify;
  if (!replies.wait(link.from_cache ? 1500 : 3000, notify)) {
    error_out = "Lock did not open an encryption session.";
    return false;
  }
  return this->parse_session_response_(notify, session, error_out);
}

bool PhysicalLockClient::open_session_with_fallback_(const Config &config, Link &link,
                                                     ReplyChannel &replies,
                                                     Session &session,
                                                     std::string &error_out) {
  if (this->open_session_(config, link, replies, session, error_out)) {
    return true;
  }
  if (!link.from_cache || !link.client->isConnected()) {
    return false;
  }
  ESP_LOGW(TAG, "Cached lock handles failed (%s); rediscovering", error_out.c_str());
  this->cached_handles_ = GattHandles{};
  if (!this->discover_handles_(link, error_out)) {
    return false;
  }
  replies.retarget(link.handles.tx);
  return this->open_session_(config, link, replies, session, error_out);
}

bool PhysicalLockClient::exchange_(const Config &config, const Session &session,
                                   const Link &link, ReplyChannel &replies,
                                   const std::vector<uint8_t> &command,
                                   std::vector<uint8_t> &response,
                                   std::string &error_out) {
  replies.drain();
  if (!this->send_encrypted_(config, session, link, command.data(), command.size(),
                             error_out)) {
    return false;
  }
  std::string notify;
  if (!replies.wait(2500, notify)) {
    error_out = "Lock did not answer the forwarded command.";
    return false;
  }
  return this->decrypt_notify_(config, session, notify, response, error_out);
}

void PhysicalLockClient::close_(Link &link) {
  // No CCCD unsubscribe: the link is not bonded, so the lock forgets the
  // notification switch on disconnect anyway — skipping it saves a round trip.
  if (link.client != nullptr) {
    link.client->disconnect();
    NimBLEDevice::deleteClient(link.client);
  }
  link = Link{};
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
                                         const Link &link,
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
  const int rc = write_handle(link.client->getConnHandle(), link.handles.rx,
                              frame.data(), frame.size());
  if (rc != 0) {
    error_out = "Could not write encrypted command to the lock (rc=" +
                std::to_string(rc) + ").";
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
