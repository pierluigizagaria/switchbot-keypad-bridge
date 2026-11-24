#include "pairing_ui.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

#include <cJSON.h>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "ble_utils.h"
#include "keypad_advert.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {
const char *const TAG = "switchbot_keypad_bridge.ui";
constexpr uint8_t SHARED_SLOT_ORIGINAL = 0x88;
constexpr uint8_t SHARED_SLOT_VISION   = 0xC6;

// Helpers to register a URI with the user_ctx set to a PairingUi instance.
httpd_uri_t make_uri(const char *path, httpd_method_t method,
                     esp_err_t (*handler)(httpd_req_t *), void *ctx) {
  httpd_uri_t u{};
  u.uri = path;
  u.method = method;
  u.handler = handler;
  u.user_ctx = ctx;
  return u;
}
}  // namespace

// ── Lifecycle ─────────────────────────────────────────────────────────────

bool PairingUi::start(uint16_t port) {
  if (this->server_ != nullptr) {
    return true;
  }
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.server_port = port;
  cfg.max_uri_handlers = 12;
  cfg.uri_match_fn = httpd_uri_match_wildcard;
  cfg.stack_size = 8192;  // headroom for the BLE scan run from /api/keypads
  cfg.lru_purge_enable = true;
  // Browsers open up to 6 keep-alive connections; with the default of 7 the
  // wizard could starve LWIP's socket pool (shared with the HA API, log
  // streams and the cloud TLS client → "failed to create socket"). 4 is
  // plenty for one wizard page, and LRU purge recycles idle sessions.
  cfg.max_open_sockets = 4;

  if (httpd_start(&this->server_, &cfg) != ESP_OK) {
    ESP_LOGE(TAG, "httpd_start failed on port %u", port);
    this->server_ = nullptr;
    return false;
  }
  this->last_activity_ms_.store(millis(), std::memory_order_relaxed);

  auto reg = [this](const char *path, httpd_method_t m,
                    esp_err_t (*h)(httpd_req_t *)) {
    httpd_uri_t u = make_uri(path, m, h, this);
    httpd_register_uri_handler(this->server_, &u);
  };
  reg("/",                  HTTP_GET,  PairingUi::handle_root_);
  reg("/api/login",         HTTP_POST, PairingUi::handle_login_);
  reg("/api/keypads",       HTTP_GET,  PairingUi::handle_keypads_);
  reg("/api/pair",          HTTP_POST, PairingUi::handle_pair_);
  reg("/api/pair/status",   HTTP_GET,  PairingUi::handle_pair_status_);
  reg("/api/locks",            HTTP_GET,  PairingUi::handle_locks_);
  reg("/api/lock/link",        HTTP_POST, PairingUi::handle_lock_link_);
  reg("/api/lock/link/status", HTTP_GET,  PairingUi::handle_lock_link_status_);

  ESP_LOGI(TAG, "Setup UI listening on http://<device>:%u/", port);
  return true;
}

void PairingUi::stop() {
  if (this->server_ != nullptr) {
    httpd_stop(this->server_);
    this->server_ = nullptr;
  }
  this->last_activity_ms_.store(0, std::memory_order_relaxed);
}

bool PairingUi::stop_if_idle(uint32_t now_ms, uint32_t timeout_ms) {
  if (this->server_ == nullptr) {
    return false;
  }
  const uint32_t last = this->last_activity_ms_.load(std::memory_order_relaxed);
  if (last == 0 || static_cast<uint32_t>(now_ms - last) < timeout_ms) {
    return false;
  }
  // Never pull the server out from under a running BLE job: the browser may
  // be gone, but the job's completion still has to be observed (poll_jobs).
  if (this->pairer_.state() == KeypadPairer::State::RUNNING ||
      this->linker_.state() == LockLinker::State::RUNNING) {
    return false;
  }
  this->stop();
  return true;
}

void PairingUi::poll_jobs() {
  // Runs every main-loop iteration, so the cheap state()/flag checks come
  // first; the full Status snapshot (string copies) is taken only on the
  // one iteration that actually consumes a SUCCESS.
  std::string pairing_job_id;
  std::string pairing_keypad_name;
  bool pairing_armed = false;
  std::string link_job_id;
  bool link_armed = false;
  {
    std::lock_guard<std::mutex> lk(this->jobs_mu_);
    pairing_armed = !this->success_notified_ && !this->pairing_job_id_.empty();
    if (pairing_armed) {
      pairing_job_id = this->pairing_job_id_;
      pairing_keypad_name = this->pairing_keypad_name_;
    }
    link_armed = !this->link_notified_ && !this->link_job_id_.empty();
    if (link_armed) {
      link_job_id = this->link_job_id_;
    }
  }

  if (pairing_armed && this->pairer_.state() == KeypadPairer::State::SUCCESS) {
    const KeypadPairer::Status st = this->pairer_.status();
    if (st.job_id == pairing_job_id) {
      bool notify = false;
      {
        std::lock_guard<std::mutex> lk(this->jobs_mu_);
        if (!this->success_notified_ && this->pairing_job_id_ == st.job_id) {
          this->success_notified_ = true;
          this->keypad_paired_.store(true);
          notify = true;
        }
      }
      // Fire outside jobs_mu_: callbacks belong to the bridge, not the UI's
      // internal bookkeeping, and should not run while a UI mutex is held.
      if (notify && this->on_paired_cb_) {
        this->on_paired_cb_(pairing_keypad_name, st.keypad_mac, st.family);
      }
    }
  }

  if (link_armed && this->linker_.state() == LockLinker::State::SUCCESS) {
    const LockLinker::Status st = this->linker_.status();
    if (st.job_id == link_job_id) {
      bool notify = false;
      {
        std::lock_guard<std::mutex> lk(this->jobs_mu_);
        if (!this->link_notified_ && this->link_job_id_ == st.job_id) {
          this->link_notified_ = true;
          this->lock_linked_.store(true);
          notify = true;
        }
      }
      if (notify && this->on_lock_linked_cb_) {
        this->on_lock_linked_cb_(st.name, st.mac, st.model, st.slot_id);
      }
    }
  }
}

void PairingUi::clear_job_notifications() {
  std::lock_guard<std::mutex> lock(this->jobs_mu_);
  this->pairing_job_id_.clear();
  this->link_job_id_.clear();
  this->success_notified_ = true;
  this->link_notified_ = true;
}

void PairingUi::touch_activity_() {
  this->last_activity_ms_.store(millis(), std::memory_order_relaxed);
}

// ── URI handlers ──────────────────────────────────────────────────────────

esp_err_t PairingUi::handle_root_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  if (self->html_ == nullptr || self->html_len_ == 0) {
    return reply_error_(req, "500 Internal Server Error",
                        "Setup UI was not embedded in this build.");
  }
  httpd_resp_set_type(req, "text/html; charset=utf-8");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  // The page is stored gzip-compressed in flash (see __init__.py). Served
  // as-is without checking Accept-Encoding: every browser accepts gzip.
  httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
  return httpd_resp_send(req, reinterpret_cast<const char *>(self->html_),
                         static_cast<ssize_t>(self->html_len_));
}

namespace {

// Serialize a cJSON node to a compact string, then free the node. cJSON owns
// the escaping, so callers never hand-build JSON. Returns `fallback` if
// allocation fails (only under OOM).
std::string json_take(cJSON *node, const char *fallback = "{}") {
  std::string out = fallback;
  if (node != nullptr) {
    char *s = cJSON_PrintUnformatted(node);
    if (s != nullptr) {
      out = s;
      cJSON_free(s);
    }
    cJSON_Delete(node);
  }
  return out;
}

// Pull a top-level JSON string property out of a request body. Returns empty
// when the body isn't valid JSON or the field is absent / not a string.
std::string extract_json_str(const std::string &body, const char *key) {
  cJSON *root = cJSON_ParseWithLength(body.data(), body.size());
  if (root == nullptr) return "";
  std::string out;
  cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
  if (cJSON_IsString(item) && item->valuestring != nullptr) {
    out = item->valuestring;
  }
  cJSON_Delete(root);
  return out;
}

bool parse_key_id_hex(const std::string &hex, uint8_t &out) {
  if (hex.empty()) return false;
  char *end = nullptr;
  const long value = std::strtol(hex.c_str(), &end, 16);
  if (end == hex.c_str() || end == nullptr || *end != '\0' ||
      value < 0 || value > 0xFF) {
    return false;
  }
  out = static_cast<uint8_t>(value);
  return true;
}

uint8_t shared_slot_for_family(KeypadFamily family) {
  return family == KeypadFamily::VISION ? SHARED_SLOT_VISION : SHARED_SLOT_ORIGINAL;
}

const CloudClient::AccountDevice *find_account_device_(
    const std::vector<CloudClient::AccountDevice> &devices,
    const std::string &mac) {
  for (const auto &dev : devices) {
    if (dev.mac_pretty == mac || dev.mac == mac) {
      return &dev;
    }
  }
  return nullptr;
}

bool fetch_comm_key_16_(CloudClient &cloud,
                        const CloudClient::AccountDevice &device,
                        const char *device_label,
                        uint8_t &key_id,
                        std::array<uint8_t, 16> &key,
                        std::string &err) {
  std::string key_id_hex;
  std::vector<uint8_t> key_bytes;
  if (!cloud.fetch_device_key(device.mac, key_id_hex, key_bytes, err)) {
    return false;
  }
  if (key_bytes.size() != key.size()) {
    err = "SwitchBot returned a malformed ";
    err += device_label;
    err += " key.";
    return false;
  }
  if (!parse_key_id_hex(key_id_hex, key_id)) {
    err = "SwitchBot returned a malformed ";
    err += device_label;
    err += " key id.";
    return false;
  }
  std::memcpy(key.data(), key_bytes.data(), key.size());
  return true;
}

template <typename LabelFn>
std::string job_started_json_(const std::string &job_id, uint8_t step_count,
                              LabelFn label_fn) {
  cJSON *resp = cJSON_CreateObject();
  cJSON_AddStringToObject(resp, "job_id", job_id.c_str());
  cJSON *labels = cJSON_AddArrayToObject(resp, "labels");
  for (uint8_t i = 0; i < step_count; ++i) {
    cJSON_AddItemToArray(labels, cJSON_CreateString(label_fn(i)));
  }
  return json_take(resp);
}

// One nearby BLE device: strongest RSSI seen plus its SwitchBot service-data
// blob (so the UI can identify the keypad model the pySwitchbot way). rssi
// starts below any real BLE reading so the first packet always wins.
struct NearbyDevice {
  int rssi{-128};
  std::vector<uint8_t> svc_data;
};

// Active-scan for `duration_ms` and record, for each advertising address
// (upper-case, colon-separated), the strongest RSSI and its SwitchBot service
// data. Lets the UI flag which account keypads are reachable right now and
// identify their model straight from the advertisement.
std::map<std::string, NearbyDevice> scan_nearby(uint32_t duration_ms) {
  std::map<std::string, NearbyDevice> seen;
  NimBLEScan *scan = NimBLEDevice::getScan();
  configure_switchbot_scan(scan);

  NimBLEScanResults results = scan->getResults(duration_ms, false);
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice *adv = results.getDevice(i);
    const std::string mac = upper_mac(adv->getAddress().toString());
    const int rssi = adv->getRSSI();
    NearbyDevice &dev = seen[mac];  // inserts a default entry on first sight
    if (rssi > dev.rssi) dev.rssi = rssi;
    // The 0xFD3D service data rides in the scan response, which usually arrives
    // as a separate packet at a different RSSI than the plain advertisement.
    // Capture it whenever a packet carries it — independent of RSSI. Gating this
    // on "strongest RSSI seen" (as before) dropped a keypad's service data
    // whenever its adv packet was stronger than its scan response, leaving the
    // device looking like a non-keypad. With two keypads in range that flakily
    // hid one or the other depending on packet order.
    std::vector<uint8_t> sd = switchbot_service_data(adv);
    if (!sd.empty()) dev.svc_data = std::move(sd);
  }
  scan->clearResults();
  return seen;
}

}  // namespace

esp_err_t PairingUi::handle_login_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  std::string body = read_body_(req);
  std::string email    = extract_json_str(body, "email");
  std::string password = extract_json_str(body, "password");
  if (email.empty() || password.empty()) {
    return reply_error_(req, "400 Bad Request", "Missing email or password.");
  }
  ESP_LOGI(TAG, "POST /api/login email=%s", email.c_str());

  std::string err;
  if (!self->cloud_.login(email, password, err)) {
    ESP_LOGW(TAG, "Login failed: %s", err.c_str());
    return reply_error_(req, "401 Unauthorized", err);
  }
  cJSON *resp = cJSON_CreateObject();
  cJSON_AddStringToObject(resp, "region", self->cloud_.region().c_str());
  cJSON_AddBoolToObject(resp, "keypad_paired", self->keypad_paired_.load());
  cJSON_AddBoolToObject(resp, "lock_linked", self->lock_linked_.load());
  return reply_json_(req, json_take(resp).c_str());
}

esp_err_t PairingUi::handle_keypads_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }
  std::vector<CloudClient::AccountDevice> devices;
  std::string err;
  if (!self->cloud_.list_devices(devices, err)) {
    ESP_LOGW(TAG, "list_devices failed: %s", err.c_str());
    return reply_error_(req, "502 Bad Gateway", err);
  }

  // Cross-reference the account devices against a fresh BLE scan: this both
  // shows which ones are in range (and how strong the signal is) and identifies
  // the keypad model straight from the advertisement (pySwitchbot-style).
  // 8 s: keypads are battery devices that advertise infrequently when idle, and
  // the radio is time-shared with WiFi and the lock advertising — a short window
  // often catches only one of several keypads. A longer scan reliably finds all.
  const std::map<std::string, NearbyDevice> nearby = scan_nearby(8000);

  cJSON *arr = cJSON_CreateArray();
  unsigned shown = 0;
  for (const auto &k : devices) {
    const auto hit = nearby.find(k.mac_pretty);
    if (hit == nearby.end()) continue;  // not in BLE range right now

    // Identify from the live advertisement. A keypad's signature rides in the
    // 0xFD3D service data, which for the Keypad Vision only arrives in the
    // (intermittently received) scan response. So cache every positive
    // identification by MAC and fall back to it on later scans where the
    // service data was missed — as long as the device is still in range. This
    // is what keeps the Vision from flickering in and out of the list.
    KeypadIdent ident =
        identify_keypad(hit->second.svc_data.data(), hit->second.svc_data.size());
    if (ident.is_keypad) {
      self->identified_keypads_[k.mac_pretty] = ident;
    } else {
      const auto cached = self->identified_keypads_.find(k.mac_pretty);
      if (cached != self->identified_keypads_.end()) ident = cached->second;
    }
    if (!ident.is_keypad) continue;

    ESP_LOGI(TAG, "keypad '%s' %s family=%s rssi=%d", k.name.c_str(),
             k.mac_pretty.c_str(), keypad_family_str(ident.family),
             hit->second.rssi);

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "mac", k.mac_pretty.c_str());
    cJSON_AddStringToObject(o, "name", k.name.c_str());
    // The pairing dialect (and which steps the wizard shows) follows from the
    // family detected here. The browser echoes it back on /api/pair so the
    // step list is correct before the pairer re-confirms it over BLE.
    cJSON_AddStringToObject(o, "family", keypad_family_str(ident.family));
    cJSON_AddBoolToObject(o, "online", true);
    cJSON_AddNumberToObject(o, "rssi", hit->second.rssi);
    cJSON_AddItemToArray(arr, o);
    ++shown;
  }
  ESP_LOGI(TAG, "GET /api/keypads -> %u keypad(s) of %u account device(s), %u nearby",
           shown, static_cast<unsigned>(devices.size()),
           static_cast<unsigned>(nearby.size()));
  return reply_json_(req, json_take(arr, "[]").c_str());
}

esp_err_t PairingUi::handle_locks_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }
  if (!self->keypad_paired_.load()) {
    return reply_error_(req, "409 Conflict", "Link a keypad before linking a lock.");
  }

  std::vector<CloudClient::AccountDevice> devices;
  std::string err;
  if (!self->cloud_.list_devices(devices, err)) {
    ESP_LOGW(TAG, "list_devices failed: %s", err.c_str());
    return reply_error_(req, "502 Bad Gateway", err);
  }

  const std::map<std::string, NearbyDevice> nearby = scan_nearby(8000);
  cJSON *arr = cJSON_CreateArray();
  unsigned shown = 0;
  for (const auto &dev : devices) {
    const PhysicalLockModel model = physical_lock_model_from_api_type(dev.device_type);
    if (model == PhysicalLockModel::UNKNOWN) continue;

    const auto hit = nearby.find(dev.mac_pretty);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "mac", dev.mac_pretty.c_str());
    cJSON_AddStringToObject(o, "name", dev.name.c_str());
    cJSON_AddStringToObject(o, "model", physical_lock_model_str(model));
    cJSON_AddStringToObject(o, "device_type", dev.device_type.c_str());
    cJSON_AddBoolToObject(o, "online", hit != nearby.end());
    if (hit != nearby.end()) {
      cJSON_AddNumberToObject(o, "rssi", hit->second.rssi);
    } else {
      cJSON_AddNullToObject(o, "rssi");
    }
    cJSON_AddItemToArray(arr, o);
    ++shown;
  }
  ESP_LOGI(TAG, "GET /api/locks -> %u lock(s) of %u account device(s)",
           shown, static_cast<unsigned>(devices.size()));
  return reply_json_(req, json_take(arr, "[]").c_str());
}

esp_err_t PairingUi::handle_lock_link_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  if (self->keypad_gcm_enabled_) {
    return reply_error_(req, "409 Conflict", "GCM keypad mode supports standalone operation only.");
  }
  std::string body = read_body_(req);
  std::string mac = extract_json_str(body, "mac");
  if (mac.empty()) {
    return reply_error_(req, "400 Bad Request", "Missing lock mac.");
  }
  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }
  if (!self->keypad_paired_.load()) {
    return reply_error_(req, "409 Conflict", "Link a keypad before linking a lock.");
  }
  // Same one-shot rule as /api/pair: re-linking goes through Reset.
  if (self->lock_linked_.load()) {
    return reply_error_(req, "409 Conflict",
                        "A lock is already linked to this bridge. "
                        "Press the Reset button to start over.");
  }

  std::vector<CloudClient::AccountDevice> devices;
  std::string err;
  if (!self->cloud_.list_devices(devices, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }
  const CloudClient::AccountDevice *found = find_account_device_(devices, mac);
  if (found == nullptr) {
    return reply_error_(req, "404 Not Found", "Lock not in this SwitchBot account.");
  }

  const PhysicalLockModel model = physical_lock_model_from_api_type(found->device_type);
  if (model == PhysicalLockModel::UNKNOWN) {
    return reply_error_(req, "400 Bad Request", "This SwitchBot device is not a supported Lock.");
  }

  // Bootstrap only: the lock communication key lets us install the bridge's
  // shared keypad/lock key into the lock slot. It is not returned by the job,
  // persisted to NVS, or used for day-to-day relay.
  uint8_t lock_key_id = 0;
  std::array<uint8_t, 16> lock_key{};
  if (!fetch_comm_key_16_(self->cloud_, *found, "lock provisioning",
                          lock_key_id, lock_key, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }

  LockLinker::Request lr;
  lr.name = found->name;
  lr.mac = found->mac_pretty;
  lr.model = model;
  lr.shared_key = self->shared_key_;
  lr.shared_slot_id = shared_slot_for_family(
      static_cast<KeypadFamily>(self->keypad_family_.load()));
  lr.lock_key_id = lock_key_id;
  lr.lock_key = lock_key;

  std::string job_id = self->linker_.start(std::move(lr));
  if (job_id.empty()) {
    return reply_error_(req, "409 Conflict",
                        "A lock-link job is already in progress.");
  }
  {
    std::lock_guard<std::mutex> lk(self->jobs_mu_);
    self->link_job_id_   = job_id;
    self->link_notified_ = false;
  }

  return reply_json_(req,
                     job_started_json_(job_id, LockLinker::step_count(),
                                       [](uint8_t i) {
                                         return LockLinker::step_label(i);
                                       })
                         .c_str());
}

esp_err_t PairingUi::handle_pair_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  std::string body = read_body_(req);
  std::string mac  = extract_json_str(body, "mac");
  if (mac.empty()) {
    return reply_error_(req, "400 Bad Request", "Missing keypad mac.");
  }
  // Family as identified by /api/keypads and echoed back by the browser. It
  // sizes the step list shown during pairing; the pairer re-confirms it from
  // the live advertisement before acting.
  const KeypadFamily family = keypad_family_from_str(extract_json_str(body, "family").c_str());
  ESP_LOGI(TAG, "POST /api/pair mac=%s family=%s", mac.c_str(), keypad_family_str(family));

  if (!self->cloud_.is_logged_in()) {
    return reply_error_(req, "401 Unauthorized", "Sign in first.");
  }
  // Pairing is a one-shot: once confirmed it can only be redone through the
  // Reset button (which also rotates the shared key). Without this gate the
  // wizard's tabs could quietly re-run the whole handshake.
  if (self->keypad_paired_.load()) {
    return reply_error_(req, "409 Conflict",
                        "A keypad is already linked to this bridge. "
                        "Press the Reset button to start over.");
  }

  // Confirm the MAC belongs to this account (and grab its pretty form + name).
  std::vector<CloudClient::AccountDevice> devices;
  std::string err;
  if (!self->cloud_.list_devices(devices, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }
  const CloudClient::AccountDevice *found = find_account_device_(devices, mac);
  if (found == nullptr) {
    return reply_error_(req, "404 Not Found",
                        "Keypad not in this SwitchBot account.");
  }
  ESP_LOGI(TAG, "/api/pair matched keypad '%s' (%s)",
           found->name.c_str(), found->mac_pretty.c_str());

  // Fetch the keypad's current communication key from the SwitchBot cloud.
  uint8_t key_id = 0;
  std::array<uint8_t, 16> key{};
  if (!fetch_comm_key_16_(self->cloud_, *found, "keypad", key_id, key, err)) {
    return reply_error_(req, "502 Bad Gateway", err);
  }

  // Build the pairer's request.
  KeypadPairer::Request kr;
  kr.keypad_mac  = found->mac_pretty;
  kr.family      = family;
  kr.key_id     = static_cast<int>(key_id);
  kr.key.assign(key.begin(), key.end());
  kr.shared_token = self->shared_key_;
  kr.esp_mac = addr_bytes(NimBLEDevice::getAddress());

  // Capture the name now — it belongs to this exact job.
  const std::string keypad_name = found->name;

  std::string job_id = self->pairer_.start(std::move(kr));
  if (job_id.empty()) {
    return reply_error_(req, "409 Conflict",
                        "A keypad link job is already in progress.");
  }
  // Bind name + job id together, then arm the one-shot flag. start() has
  // already moved the job to RUNNING, so poll_jobs() can no longer observe
  // a previous job's lingering SUCCESS state.
  {
    std::lock_guard<std::mutex> lk(self->jobs_mu_);
    self->pairing_keypad_name_ = keypad_name;
    self->pairing_job_id_      = job_id;
    self->success_notified_    = false;
  }
  return reply_json_(req,
                     job_started_json_(job_id, KeypadPairer::step_count(family),
                                       [family](uint8_t i) {
                                         return KeypadPairer::step_label(family, i);
                                       })
                         .c_str());
  // Step labels for the progress stepper — the wizard renders these, so the
  // pairer stays the single source of truth for count, order and wording.
  // The Vision family has one extra step (enabling the doorbell).
}

// Serialize a job snapshot for the wizard's polling loop. Success callbacks
// are NOT fired here — poll_jobs() owns that from the main loop, so a job
// completes correctly even when the browser stopped polling.
namespace {
std::string job_status_json(uint8_t step, uint8_t total,
                            const std::string &message, bool done,
                            bool failed, const std::string &error) {
  cJSON *resp = cJSON_CreateObject();
  cJSON_AddNumberToObject(resp, "step", step);
  cJSON_AddNumberToObject(resp, "total", total);
  cJSON_AddStringToObject(resp, "message", message.c_str());
  cJSON_AddBoolToObject(resp, "done", done);
  if (failed) {
    cJSON_AddStringToObject(resp, "error", error.c_str());
  } else {
    cJSON_AddNullToObject(resp, "error");
  }
  return json_take(resp);
}

template <typename Status, typename State>
std::string job_status_json_(const Status &st, State success_state,
                             State failed_state) {
  const bool failed = st.state == failed_state;
  const bool done = failed || st.state == success_state;
  return job_status_json(st.step, st.total, st.message, done, failed, st.error);
}
}  // namespace

esp_err_t PairingUi::handle_pair_status_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  const KeypadPairer::Status st = self->pairer_.status();
  return reply_json_(
      req, job_status_json_(st, KeypadPairer::State::SUCCESS,
                            KeypadPairer::State::FAILED)
               .c_str());
}

esp_err_t PairingUi::handle_lock_link_status_(httpd_req_t *req) {
  auto *self = static_cast<PairingUi *>(req->user_ctx);
  self->touch_activity_();
  const LockLinker::Status st = self->linker_.status();
  return reply_json_(
      req, job_status_json_(st, LockLinker::State::SUCCESS,
                            LockLinker::State::FAILED)
               .c_str());
}

// ── Helpers ───────────────────────────────────────────────────────────────

esp_err_t PairingUi::reply_json_(httpd_req_t *req, const char *json,
                                 const char *status) {
  httpd_resp_set_status(req, status);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

esp_err_t PairingUi::reply_error_(httpd_req_t *req, const char *status,
                                  const std::string &message) {
  cJSON *body = cJSON_CreateObject();
  cJSON_AddStringToObject(body, "error", message.c_str());
  return reply_json_(req, json_take(body).c_str(), status);
}

std::string PairingUi::read_body_(httpd_req_t *req) {
  std::string buf;
  // Login / pair payloads are a few hundred bytes at most; refuse anything
  // larger so a bogus Content-Length cannot drive a huge heap allocation.
  constexpr size_t MAX_BODY_LEN = 2048;
  if (req->content_len == 0 || req->content_len > MAX_BODY_LEN) {
    return buf;
  }
  // httpd_req_recv may legitimately return less than content_len (the body
  // can arrive split across TCP segments), so keep reading until complete.
  buf.resize(req->content_len);
  size_t received = 0;
  while (received < req->content_len) {
    int r = httpd_req_recv(req, buf.data() + received,
                           static_cast<int>(req->content_len - received));
    if (r <= 0) {
      buf.clear();
      return buf;
    }
    received += static_cast<size_t>(r);
  }
  return buf;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
