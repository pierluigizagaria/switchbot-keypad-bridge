#include "switchbot_keypad_bridge.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include <esp_mac.h>
#include <esp_random.h>
#include <psa/crypto.h>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "ble_utils.h"
#include "keypad_advert.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge";

// SwitchBot's OUI. Applied to the chip's factory MAC at boot so the bridge
// advertises within SwitchBot's address range — the Keypad Vision filters
// scan results on this prefix.
constexpr uint8_t SPOOFED_OUI[3] = {0xB0, 0xE9, 0xFE};

// Manufacturer-specific advertising blob published by the genuine lock.
constexpr uint8_t ADVERTISING_MFG_DATA[] = {0x27, 0x09, 0x00, 0x10,
                                            0xA5, 0xB8, 0x00, 0x00, 0x00};

// Encrypted response payloads sent back to the keypad on lock/unlock.
constexpr uint8_t RESPONSE_LOCK[5]   = {0x90, 0x0A, 0x7F, 0x7F, 0x00};
constexpr uint8_t RESPONSE_UNLOCK[5] = {0x98, 0x08, 0x7F, 0x7F, 0x00};

// Trailing 13 bytes appended to the lock-state byte when answering a state poll.
constexpr uint8_t STATE_PAYLOAD_TAIL[13] = {0x08, 0x08, 0x41, 0x00, 0x00, 0x00, 0x00,
                                            0x80, 0xF2, 0xFB, 0x00, 0x00, 0x00};

constexpr uint8_t SHARED_SLOT_ORIGINAL = 0x88;
constexpr uint8_t SHARED_SLOT_VISION   = 0xC6;

constexpr size_t AES_KEY_SIZE = 16;

// Battery advert scan: one short active window per interval.
constexpr uint32_t BATTERY_SCAN_DURATION_MS = 5000;
constexpr uint32_t BATTERY_SCAN_RETRY_MS    = 30000;

bool is_shared_slot(uint8_t slot) {
  return slot == SHARED_SLOT_ORIGINAL || slot == SHARED_SLOT_VISION;
}

}  // namespace

// ---------------------------------------------------------------------------
// NimBLE callback bridges
// ---------------------------------------------------------------------------

class SwitchbotKeypadBridge::ServerCallbacks : public NimBLEServerCallbacks {
 public:
  explicit ServerCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override {
    this->parent_->push_connect_();
  }

  void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override {
    this->parent_->push_disconnect_();
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::RxCharCallbacks : public NimBLECharacteristicCallbacks {
 public:
  explicit RxCharCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onWrite(NimBLECharacteristic *characteristic, NimBLEConnInfo &info) override {
    const std::string value = characteristic->getValue();
    if (value.empty())
      return;
    this->parent_->push_rx_(value);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::BatteryScanCallbacks : public NimBLEScanCallbacks {
 public:
  explicit BatteryScanCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onResult(const NimBLEAdvertisedDevice *adv) override {
    this->parent_->handle_battery_advert_(adv);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

// ---------------------------------------------------------------------------
// Thread-safe event queueing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::push_connect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::CONNECT, ""});
}

void SwitchbotKeypadBridge::push_disconnect_() {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::DISCONNECT, ""});
}

void SwitchbotKeypadBridge::push_rx_(const std::string &frame) {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back({QueuedEvent::RX, frame});
}

// ---------------------------------------------------------------------------
// Component lifecycle
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::setup() {
  // Load — or, on first boot, generate — the 16-byte AES-128 session key.
  // reset_pairing() rotates it; it is never part of the YAML config.
  this->shared_key_pref_ =
      global_preferences->make_preference<std::array<uint8_t, 16>>(0x534B4559UL /* 'SKEY' */);
  if (!this->shared_key_pref_.load(&this->shared_key_)) {
    this->create_shared_key_();
    ESP_LOGI(TAG, "Generated a fresh shared key");
  }

  // Restore the linked keypad name (if any) and publish it to the sensor.
  this->keypad_name_pref_ = global_preferences->make_preference<char[KEYPAD_NAME_MAX]>(
      0x534B5042UL /* 'SKPB' */);
  char stored_name[KEYPAD_NAME_MAX] = {};
  bool have_keypad = false;
  if (this->keypad_name_pref_.load(&stored_name) && stored_name[0] != '\0') {
    stored_name[KEYPAD_NAME_MAX - 1] = '\0';
    have_keypad = true;
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(stored_name);
    }
    ESP_LOGI(TAG, "Linked keypad: '%s'", stored_name);
  } else {
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state("Unlinked");
    }
  }
  this->keypad_paired_ = have_keypad;
  this->pairing_ui_.set_keypad_paired(have_keypad);

  // Restore the keypad MAC + family used by the battery advert scan. Missing
  // for keypads linked before this field existed — the scan learns it then.
  this->keypad_info_pref_ =
      global_preferences->make_preference<KeypadInfo>(0x534B4D43UL /* 'SKMC' */);
  if (!this->keypad_info_pref_.load(&this->keypad_info_)) {
    this->keypad_info_ = KeypadInfo{};
  }
  if (this->keypad_info_.valid != 0) {
    this->pairing_ui_.set_keypad_family(
        static_cast<KeypadFamily>(this->keypad_info_.family));
  }
  this->linked_lock_pref_ =
      global_preferences->make_preference<LinkedLockInfo>(0x534C4F43UL /* 'SLOC' */);
  if (!this->linked_lock_pref_.load(&this->linked_lock_info_)) {
    this->linked_lock_info_ = LinkedLockInfo{};
  } else {
    bool had_private_key_material = false;
    for (uint8_t b : this->linked_lock_info_.reserved) {
      if (b != 0) {
        had_private_key_material = true;
        break;
      }
    }
    if (this->linked_lock_info_.valid != 0 &&
        (had_private_key_material || !is_shared_slot(this->linked_lock_info_.slot_id))) {
      ESP_LOGW(TAG, "Ignoring legacy linked-lock record that was not shared-key based");
      this->linked_lock_info_ = LinkedLockInfo{};
      this->save_and_sync_(this->linked_lock_pref_, &this->linked_lock_info_);
    }
  }
  this->lock_linked_ = this->linked_lock_info_.valid != 0;
  this->pairing_ui_.set_lock_linked(this->lock_linked_);
  this->publish_linked_lock_();
  this->battery_scan_callbacks_ = new BatteryScanCallbacks(this);
  this->next_battery_scan_at_ = millis() + BATTERY_SCAN_RETRY_MS;
  if (!this->lock_linked_) {
    this->clear_lock_battery_();
  }

  if (!this->prepare_keys_() || !this->prepare_ble_()) {
    this->mark_failed();
    return;
  }
  ESP_LOGI(TAG, "Ready. Advertising on %s",
           NimBLEDevice::getAddress().toString().c_str());

  this->pairing_ui_.set_shared_key(this->shared_key_);
  this->pairing_ui_.set_on_paired_callback(
      [this](const std::string &name, const std::string &mac,
             KeypadFamily family) {
        // Runs from PairingUi::poll_jobs() in loop(); keep the apply path
        // centralized below so publishing and NVS writes stay in one place.
        this->pending_keypad_name_ = name;
        this->pending_keypad_mac_ = mac;
        this->pending_keypad_family_ = family;
        this->pending_pair_apply_.store(true, std::memory_order_release);
      });
  this->pairing_ui_.set_on_lock_linked_callback(
      [this](const std::string &name, const std::string &mac,
             PhysicalLockModel model, uint8_t slot_id) {
        this->pending_lock_name_ = name;
        this->pending_lock_mac_ = mac;
        this->pending_lock_model_ = model;
        this->pending_lock_slot_id_ = slot_id;
        this->pending_lock_apply_.store(true, std::memory_order_release);
      });
  // Setup mode: with no keypad linked yet, open the wizard right away
  // so the very first link needs no button press.
  if (!have_keypad) {
    if (this->pairing_ui_.start()) {
      ESP_LOGI(TAG, "No keypad linked — starting setup mode");
    } else {
      ESP_LOGW(TAG, "Setup UI failed to start; check port 80 is free");
    }
  }
}

void SwitchbotKeypadBridge::loop() {
  // Observe finished wizard jobs from the main loop — this queues the pending
  // applies below even when the browser stopped polling mid-job.
  if (this->pairing_ui_.is_running()) {
    this->pairing_ui_.poll_jobs();
  }

  this->apply_pending_pairing_();
  this->apply_pending_lock_link_();
  this->apply_pending_lock_relay_();

  // Idle-close the wizard only once a keypad is linked: with nothing linked
  // the wizard is the device's whole purpose ("setup mode") and must stay
  // reachable — closing it would strand the first-boot flow behind the Reset
  // button, which needlessly rotates the shared key.
  if (this->keypad_paired_ && this->pairing_ui_.stop_if_idle(millis())) {
    ESP_LOGI(TAG, "Setup UI stopped after 5 minutes of inactivity");
  }

  // Drain the RX queue. Swapping the vector out keeps the critical section
  // free of allocation and copying, so the NimBLE task never waits on it.
  std::vector<QueuedEvent> pending;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    pending.swap(this->rx_queue_);
  }

  for (const auto &ev : pending) {
    if (ev.type == QueuedEvent::CONNECT) {
      ESP_LOGI(TAG, "Keypad connected");
      this->session_.reset_transport();
    } else if (ev.type == QueuedEvent::DISCONNECT) {
      ESP_LOGI(TAG, "Keypad disconnected, restarting advertising");
      this->session_.reset_transport();
      NimBLEDevice::startAdvertising();
    } else if (ev.type == QueuedEvent::RX) {
      this->on_rx_frame_(ev.frame);
    }
  }

  if (this->keypad_battery_level_sensor_ != nullptr ||
      this->lock_battery_level_sensor_ != nullptr) {
    this->apply_pending_keypad_battery_();
    this->apply_pending_lock_battery_();
    this->maybe_finish_battery_scan_();
    this->maybe_start_battery_scan_();
  }
}

void SwitchbotKeypadBridge::apply_pending_pairing_() {
  if (this->pending_pair_apply_.exchange(false, std::memory_order_acquire)) {
    const std::string &name = this->pending_keypad_name_;

    // Persist the name so it survives a reboot and can be re-published.
    char buf[KEYPAD_NAME_MAX] = {};
    name.copy(buf, sizeof(buf) - 1);
    const bool saved = this->keypad_name_pref_.save(&buf);

    // Persist the keypad's MAC + family for the battery advert scan.
    KeypadInfo info{};
    if (parse_mac_pretty(this->pending_keypad_mac_, info.mac)) {
      info.family = static_cast<uint8_t>(this->pending_keypad_family_);
      info.valid = 1;
    }
    this->keypad_info_ = info;
    this->save_and_sync_(this->keypad_info_pref_, &this->keypad_info_);

    this->keypad_paired_ = true;
    this->pairing_ui_.set_keypad_paired(true);
    this->pairing_ui_.set_keypad_family(this->pending_keypad_family_);
    this->last_keypad_battery_ = -1;
    // Pick the new keypad's battery up shortly, not a full interval away.
    this->next_battery_scan_at_ = millis() + 10000;

    this->publish_text_or_unlinked_(this->keypad_text_sensor_, name.c_str());
    ESP_LOGI(TAG, "Linked keypad: '%s' (nvs save %s)", name.c_str(),
             saved ? "ok" : "FAILED");

    ESP_LOGI(TAG, "Setup UI remains open for lock linking until it is idle");
  }
}

void SwitchbotKeypadBridge::apply_pending_lock_link_() {
  if (this->pending_lock_apply_.exchange(false, std::memory_order_acquire)) {
    LinkedLockInfo info{};
    if (parse_mac_pretty(this->pending_lock_mac_, info.mac)) {
      info.valid = 1;
      info.model = static_cast<uint8_t>(this->pending_lock_model_);
      info.slot_id = this->pending_lock_slot_id_;
      this->pending_lock_name_.copy(info.name, sizeof(info.name) - 1);
    }
    this->linked_lock_info_ = info;
    this->lock_linked_ = info.valid != 0;
    this->pairing_ui_.set_lock_linked(this->lock_linked_);
    this->save_and_sync_(this->linked_lock_pref_, &this->linked_lock_info_);
    this->publish_linked_lock_();
    this->clear_lock_battery_();
    this->next_battery_scan_at_ = millis() + 5000;
    if (this->lock_linked_) {
      ESP_LOGI(TAG, "Linked physical lock: '%s' (%s, shared_slot=0x%02X)",
               this->linked_lock_info_.name,
               physical_lock_model_str(static_cast<PhysicalLockModel>(this->linked_lock_info_.model)),
               this->linked_lock_info_.slot_id);
    } else {
      ESP_LOGW(TAG, "Ignoring linked lock apply with invalid MAC");
    }
  }
}

void SwitchbotKeypadBridge::apply_pending_lock_relay_() {
  if (this->pending_relay_apply_.exchange(false, std::memory_order_acquire)) {
    if (!this->relay_ok_) {
      ESP_LOGW(TAG, "Physical lock relay finished without a lock reply");
      return;
    }
    switch (this->relay_command_.type) {
      case CommandType::LOCK:
        ESP_LOGI(TAG, "Physical lock relay confirmed Lock");
        return;
      case CommandType::UNLOCK:
        ESP_LOGI(TAG, "Physical lock relay confirmed Unlock: method=%s index=%d",
                 unlock_method_name(this->relay_command_.method),
                 this->relay_command_.credential_index);
        return;
      default:
        ESP_LOGD(TAG, "Physical lock replied to forwarded command");
        return;
    }
  }
}

void SwitchbotKeypadBridge::reset_pairing() {
  ESP_LOGI(TAG, "Resetting links — rotating the shared key and re-opening the setup wizard");

  // Rotate the key and swap it into the live crypto slot: the previously
  // linked keypad can no longer command the bridge, with no reboot needed.
  this->create_shared_key_();
  if (!this->import_aes_key_()) {
    ESP_LOGE(TAG, "Key rotation failed — reset aborted");
    return;
  }

  // Stop an in-flight battery scan window: the wizard's own blocking scans
  // share the NimBLE scan singleton and must not race it.
  this->stop_battery_scan_();

  // Forget the linked keypad name and its battery-scan identity.
  char empty[KEYPAD_NAME_MAX] = {};
  this->keypad_name_pref_.save(&empty);
  this->keypad_info_ = KeypadInfo{};
  this->keypad_info_pref_.save(&this->keypad_info_);
  this->linked_lock_info_ = LinkedLockInfo{};
  this->linked_lock_pref_.save(&this->linked_lock_info_);
  global_preferences->sync();
  this->publish_text_or_unlinked_(this->keypad_text_sensor_, nullptr);
  this->lock_linked_ = false;
  this->pairing_ui_.set_lock_linked(false);
  this->publish_linked_lock_();
  this->clear_lock_battery_();
  this->keypad_paired_ = false;
  this->pairing_ui_.set_keypad_paired(false);
  this->pairing_ui_.set_keypad_family(KeypadFamily::ORIGINAL);
  this->reset_battery_sensor_(this->keypad_battery_level_sensor_,
                              this->last_keypad_battery_);

  // Invalidate any in-flight BLE session — it is keyed to the old secret —
  // and forget the learned token slot along with it.
  this->session_.reset();
  this->session_.forget_slot();

  // Re-enter setup mode straight away with the rotated key.
  this->pairing_ui_.set_shared_key(this->shared_key_);
  if (this->pairing_ui_.start()) {
    ESP_LOGI(TAG, "Reset complete — re-entering setup mode");
  } else {
    ESP_LOGW(TAG, "Setup UI failed to start; check port 80 is free");
  }
}

void ResetButton::press_action() {
  if (this->parent_->is_pairing_active()) {
    ESP_LOGW(TAG, "Setup wizard is already active, ignoring Reset action");
    return;
  }
  this->parent_->reset_pairing();
}

void ReportLockedButton::press_action() {
  ESP_LOGI(TAG, "Reporting locked state to the keypad");
  this->parent_->set_lock_state(true);
}

void SwitchbotKeypadBridge::dump_config() {
  ESP_LOGCONFIG(TAG, "SwitchBot Keypad Bridge:");
  ESP_LOGCONFIG(TAG, "  BLE address: %s", NimBLEDevice::getAddress().toString().c_str());
  ESP_LOGCONFIG(TAG, "  Setup UI: port 80");
  ESP_LOGCONFIG(TAG, "  Physical lock relay: %s",
                this->lock_linked_ ? this->linked_lock_info_.name : "Unlinked");
  if (this->keypad_battery_level_sensor_ != nullptr ||
      this->lock_battery_level_sensor_ != nullptr) {
    ESP_LOGCONFIG(TAG, "  Battery refresh interval: %us",
                  static_cast<unsigned>(this->battery_scan_interval_ms_ / 1000));
  }
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Initialization failed - see previous errors");
  }
}

void SwitchbotKeypadBridge::create_shared_key_() {
  esp_fill_random(this->shared_key_.data(), this->shared_key_.size());
  this->shared_key_pref_.save(&this->shared_key_);
  global_preferences->sync();
}

bool SwitchbotKeypadBridge::import_aes_key_() {
  // Drop any previously imported handle so the slot can be re-keyed in
  // place — reset_pairing() rotates the key without rebooting.
  if (this->aes_key_handle_ != PSA_KEY_ID_NULL) {
    psa_destroy_key(this->aes_key_handle_);
    this->aes_key_handle_ = PSA_KEY_ID_NULL;
  }

  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);
  psa_status_t status = psa_import_key(&attrs, this->shared_key_.data(), AES_KEY_SIZE,
                                       &this->aes_key_handle_);
  psa_reset_key_attributes(&attrs);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }
  this->session_.set_aes_key(this->aes_key_handle_);
  return true;
}

bool SwitchbotKeypadBridge::prepare_keys_() {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "PSA Crypto init failed (%d)", static_cast<int>(status));
    return false;
  }
  return this->import_aes_key_();
}

bool SwitchbotKeypadBridge::prepare_ble_() {
  // Spoof a SwitchBot-OUI BLE address: keep the chip-unique tail, replace
  // the leading three bytes. The Vision keypad filters scan results on this
  // prefix and would otherwise ignore the bridge. Must run before NimBLE
  // init so the controller picks up the patched base MAC.
  uint8_t base[6];
  esp_err_t err = esp_efuse_mac_get_default(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_efuse_mac_get_default failed (err=0x%X)", err);
    return false;
  }
  std::memcpy(base, SPOOFED_OUI, sizeof(SPOOFED_OUI));
  err = esp_base_mac_addr_set(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_base_mac_addr_set failed (err=0x%X)", err);
    return false;
  }
  ESP_LOGD(TAG, "Base MAC set to %02X:%02X:%02X:%02X:%02X:%02X (SwitchBot OUI spoof)",
           base[0], base[1], base[2], base[3], base[4], base[5]);

  NimBLEDevice::init("WoLock");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  this->server_ = NimBLEDevice::createServer();
  this->server_->setCallbacks(new ServerCallbacks(this));

  NimBLEService *service = this->server_->createService(SWITCHBOT_SERVICE_UUID);
  this->tx_characteristic_ =
      service->createCharacteristic(SWITCHBOT_TX_CHAR_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      SWITCHBOT_RX_CHAR_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCharCallbacks(this));

  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(service->getUUID());
  advertising->setManufacturerData(
      std::string(reinterpret_cast<const char *>(ADVERTISING_MFG_DATA), sizeof(ADVERTISING_MFG_DATA)));
  advertising->start();
  return true;
}

// ---------------------------------------------------------------------------
// RX path
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::on_rx_frame_(const std::string &frame) {
  switch (this->session_.process_frame(frame)) {
    case LockSession::Action::SEND_IV:
      this->notify_(this->session_.iv_response(), this->session_.iv_response_size());
      return;
    case LockSession::Action::COMMAND:
      this->handle_command_(this->session_.header(), this->session_.command());
      return;
    case LockSession::Action::NONE:
    default:
      return;  // dropped — the session logged why
  }
}

void SwitchbotKeypadBridge::handle_command_(const FrameHeader &header, const DecodedCommand &command) {
  // Publish decoded Home Assistant events immediately: the event reports the
  // keypad action itself, so automations must not wait for the physical
  // lock's BLE round-trip (which runs in parallel below).
  switch (command.type) {
    case CommandType::LOCK:
      ESP_LOGI(TAG, "Lock");
      this->lock_state_ = LockState::LOCKED;
      this->publish_lock_();
      break;

    case CommandType::UNLOCK:
      ESP_LOGI(TAG, "Unlock: method=%s (0x%02X) index=%d",
               unlock_method_name(command.method),
               static_cast<uint8_t>(command.method), command.credential_index);
      this->lock_state_ = LockState::UNLOCKED;
      this->publish_unlock_(command.method, command.credential_index);
      break;

    case CommandType::STATE_POLL:
      ESP_LOGV(TAG, "State poll");
      break;

    case CommandType::DOORBELL:
      ESP_LOGI(TAG, "Doorbell");
      this->publish_doorbell_();
      break;

    case CommandType::UNKNOWN:
    default:
      break;
  }

  // With a physical lock linked, answer the keypad exactly like standalone
  // mode and mirror side-effecting payloads onto the lock in the background.
  // The keypad must never wait for, or receive, the physical lock's reply.
  if (this->lock_linked_) {
    this->send_local_response_(header, command);
    switch (command.type) {
      case CommandType::LOCK:
      case CommandType::UNLOCK:
      case CommandType::UNKNOWN:
        if (!this->relay_to_lock_async_(header, command)) {
          ESP_LOGW(TAG, "Physical lock relay unavailable after local keypad response");
        }
        return;
      case CommandType::STATE_POLL:
      case CommandType::DOORBELL:
      default:
        return;
    }
  }

  // Local answer only when no physical lock is linked.
  this->send_local_response_(header, command);
}

// Answer the keypad locally. Linked-lock mode uses the same path; the lock's
// eventual reply is logged but never forwarded back to the keypad.
void SwitchbotKeypadBridge::send_local_response_(const FrameHeader &header,
                                                 const DecodedCommand &command) {
  switch (command.type) {
    case CommandType::LOCK:
      this->send_encrypted_response_(header, RESPONSE_LOCK, sizeof(RESPONSE_LOCK));
      return;
    case CommandType::UNLOCK:
      this->send_encrypted_response_(header, RESPONSE_UNLOCK, sizeof(RESPONSE_UNLOCK));
      return;
    case CommandType::STATE_POLL:
      this->handle_state_poll_(header);
      return;
    case CommandType::DOORBELL:
      this->send_ack_(header);
      return;
    case CommandType::UNKNOWN:
    default:
      this->send_ack_(header);
      return;
  }
}

void SwitchbotKeypadBridge::handle_state_poll_(const FrameHeader &header) {
  uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
  state_payload[0] = static_cast<uint8_t>(this->lock_state_);
  std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
  this->send_encrypted_response_(header, state_payload, sizeof(state_payload));
}

PhysicalLockClient::Config SwitchbotKeypadBridge::physical_lock_config_(uint8_t slot_id) const {
  PhysicalLockClient::Config cfg;
  cfg.mac = "";
  if (this->linked_lock_info_.valid != 0) {
    char mac[18];
    std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                  this->linked_lock_info_.mac[0], this->linked_lock_info_.mac[1],
                  this->linked_lock_info_.mac[2], this->linked_lock_info_.mac[3],
                  this->linked_lock_info_.mac[4], this->linked_lock_info_.mac[5]);
    cfg.mac = mac;
    cfg.model = static_cast<PhysicalLockModel>(this->linked_lock_info_.model);
    cfg.key_id = slot_id;
    cfg.key = this->shared_key_;
  }
  return cfg;
}

bool SwitchbotKeypadBridge::relay_to_lock_async_(const FrameHeader &header,
                                                 const DecodedCommand &command) {
  if (this->session_.plaintext_size() == 0) {
    ESP_LOGW(TAG, "Cannot relay command: no decrypted keypad plaintext");
    return false;
  }
  if (this->lock_relay_busy_.exchange(true)) {
    ESP_LOGW(TAG, "Lock relay still in flight — answering this command locally");
    return false;
  }
  // The relay opens a central connection; make sure the battery advert scan
  // isn't holding the radio.
  this->stop_battery_scan_();

  // Snapshot everything the task needs now: the session buffer is reused by
  // the next keypad frame, and the config must not be read off-thread.
  struct RelayCtx {
    SwitchbotKeypadBridge *self;
    PhysicalLockClient::Config cfg;
    std::vector<uint8_t> plaintext;
    DecodedCommand command;
  };
  auto *ctx = new RelayCtx{
      this, this->physical_lock_config_(header.key_id),
      {this->session_.plaintext(),
       this->session_.plaintext() + this->session_.plaintext_size()},
      command};

  BaseType_t rc = xTaskCreatePinnedToCore(
      [](void *raw) {
        auto *c = static_cast<RelayCtx *>(raw);
        std::vector<uint8_t> response;
        std::string error;
        bool result_posted = false;
        auto post_relay_result = [c, &result_posted](bool ok) {
          c->self->relay_command_  = c->command;
          c->self->relay_ok_       = ok;
          c->self->pending_relay_apply_.store(true, std::memory_order_release);
          result_posted = true;
        };
        const bool ok = c->self->physical_lock_client_.send_plaintext(
            c->cfg, c->plaintext.data(), c->plaintext.size(), response, error,
            nullptr,
            [&post_relay_result](const std::vector<uint8_t> &reply) {
              // The keypad already got its local response. This callback only
              // lets loop() log that the physical lock replied.
              (void) reply;
              post_relay_result(true);
            });
        if (!ok) {
          ESP_LOGW(TAG, "Lock relay command failed: %s", error.c_str());
        }
        // If the lock never produced a response, hand the final outcome to
        // loop() after send_plaintext() returns. Successful replies are noted
        // immediately by the callback above.
        if (!result_posted) {
          post_relay_result(ok);
        }
        c->self->lock_relay_busy_.store(false);
        delete c;
        vTaskDelete(nullptr);
      },
      "lock-relay", 8192, ctx, tskIDLE_PRIORITY + 2, nullptr,
      // Same core as the BT task, matching the pairer/linker jobs.
      0);
  if (rc != pdPASS) {
    delete ctx;
    this->lock_relay_busy_.store(false);
    ESP_LOGW(TAG, "Could not start the lock relay task");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::send_ack_(const FrameHeader &header) {
  const uint8_t ack[LockSession::HEADER_LEN] = {0x01, header.key_id, header.seq_a, header.seq_b};
  ESP_LOGV(TAG, "TX keypad ack %s",
           format_hex_pretty(ack, sizeof(ack)).c_str());
  this->notify_(ack, sizeof(ack));
}

void SwitchbotKeypadBridge::send_encrypted_response_(const FrameHeader &header,
                                                    const uint8_t *plaintext, size_t length) {
  ESP_LOGV(TAG, "TX keypad plaintext %s",
           format_hex_pretty(plaintext, length).c_str());
  uint8_t packet[LockSession::MAX_PACKET];
  const size_t n = this->session_.encrypt_response(header, plaintext, length, packet);
  if (n == 0) {
    return;  // error already logged
  }
  ESP_LOGV(TAG, "TX keypad %s", format_hex_pretty(packet, n).c_str());
  this->notify_(packet, n);
}

void SwitchbotKeypadBridge::notify_(const uint8_t *data, size_t length) {
  this->tx_characteristic_->setValue(data, length);
  this->tx_characteristic_->notify();
}

// ---------------------------------------------------------------------------
// Eventing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::publish_lock_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Lock");
  }
  this->on_lock_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_unlock_(UnlockMethod method, int index) {
  const char *method_str = unlock_method_name(method);
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Unlock");
  }
  this->on_unlock_callbacks_.call(std::string(method_str), index);
}

void SwitchbotKeypadBridge::publish_doorbell_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Doorbell");
  }
  this->on_doorbell_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_linked_lock_() {
  if (this->lock_linked_ && this->linked_lock_info_.valid != 0 &&
      this->linked_lock_info_.name[0] != '\0') {
    this->publish_text_or_unlinked_(this->linked_lock_text_sensor_,
                                    this->linked_lock_info_.name);
  } else {
    this->publish_text_or_unlinked_(this->linked_lock_text_sensor_, nullptr);
  }
}

void SwitchbotKeypadBridge::save_and_sync_(ESPPreferenceObject &pref,
                                           const KeypadInfo *value) {
  pref.save(value);
  global_preferences->sync();
}

void SwitchbotKeypadBridge::save_and_sync_(ESPPreferenceObject &pref,
                                           const LinkedLockInfo *value) {
  pref.save(value);
  global_preferences->sync();
}

void SwitchbotKeypadBridge::publish_text_or_unlinked_(
    text_sensor::TextSensor *sensor, const char *value) {
  if (sensor == nullptr) {
    return;
  }
  sensor->publish_state((value != nullptr && value[0] != '\0') ? value : "Unlinked");
}

void SwitchbotKeypadBridge::publish_battery_if_changed_(
    sensor::Sensor *sensor, int value, int &last, const char *label) {
  ESP_LOGD(TAG, "%s battery: %d%%", label, value);
  if (sensor != nullptr && value != last) {
    last = value;
    sensor->publish_state(static_cast<float>(value));
  }
}

void SwitchbotKeypadBridge::reset_battery_sensor_(sensor::Sensor *sensor,
                                                  int &last) {
  last = -1;
  if (sensor != nullptr) {
    sensor->publish_state(NAN);
  }
}

// ---------------------------------------------------------------------------
// Battery refresh (advertisement scan)
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::maybe_start_battery_scan_() {
  const uint32_t now = millis();

  if (this->battery_scan_active_.load(std::memory_order_acquire)) {
    // NimBLE drops isScanning() when the window elapses or stop() ran.
    if (!NimBLEDevice::getScan()->isScanning()) {
      this->stop_battery_scan_();
      this->next_battery_scan_at_ = now + this->battery_scan_interval_ms_;
    }
    return;
  }

  if (static_cast<int32_t>(now - this->next_battery_scan_at_) < 0) {
    return;
  }

  const bool wants_keypad =
      this->keypad_battery_level_sensor_ != nullptr && this->keypad_paired_;
  const bool wants_lock = this->lock_battery_level_sensor_ != nullptr &&
                          this->lock_linked_ &&
                          this->linked_lock_info_.valid != 0;
  if (!wants_keypad && !wants_lock) {
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
    return;
  }

  // The scan singleton is shared with the pairing flows (which run blocking
  // scans), and the keypad does not advertise while it holds a connection to
  // us — defer rather than fight either.
  if (this->background_ble_busy_() ||
      NimBLEDevice::getScan()->isScanning()) {
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
    return;
  }

  this->battery_scan_wants_keypad_ = wants_keypad;
  this->battery_scan_wants_lock_ = wants_lock;
  this->keypad_battery_scan_found_ = false;
  this->lock_battery_scan_found_ = false;
  this->battery_scan_keypad_known_ = this->keypad_info_.valid != 0;
  if (this->battery_scan_keypad_known_) {
    std::memcpy(this->battery_scan_keypad_mac_, this->keypad_info_.mac,
                sizeof(this->battery_scan_keypad_mac_));
    this->battery_scan_keypad_family_ = this->keypad_info_.family;
  }
  if (wants_lock) {
    std::memcpy(this->battery_scan_lock_mac_, this->linked_lock_info_.mac,
                sizeof(this->battery_scan_lock_mac_));
    this->battery_scan_lock_model_ =
        static_cast<PhysicalLockModel>(this->linked_lock_info_.model);
  } else {
    this->battery_scan_lock_model_ = PhysicalLockModel::UNKNOWN;
  }

  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(this->battery_scan_callbacks_, false);
  configure_switchbot_scan(scan);
  this->battery_scan_active_.store(true, std::memory_order_release);
  if (scan->start(BATTERY_SCAN_DURATION_MS, false, true)) {
    ESP_LOGD(TAG, "Battery scan window opened (%u ms)",
             static_cast<unsigned>(BATTERY_SCAN_DURATION_MS));
  } else {
    ESP_LOGW(TAG, "Battery scan failed to start");
    this->stop_battery_scan_();
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
  }
}

void SwitchbotKeypadBridge::handle_battery_advert_(const NimBLEAdvertisedDevice *adv) {
  // The callbacks stay registered on the shared scan singleton, so pairing
  // scans fire them too — only act inside our own scan window.
  if (!this->battery_scan_active_.load(std::memory_order_acquire)) {
    return;
  }

  const std::array<uint8_t, 6> mac = addr_bytes(adv->getAddress());
  const std::vector<uint8_t> sd = switchbot_service_data(adv);

  std::string mfr;
  if (adv->haveManufacturerData()) {
    mfr = adv->getManufacturerData();
  }

  if (this->battery_scan_wants_keypad_ && !this->keypad_battery_scan_found_) {
    bool keypad_match = false;
    KeypadFamily family = KeypadFamily::ORIGINAL;
    if (this->battery_scan_keypad_known_) {
      keypad_match =
          std::memcmp(mac.data(), this->battery_scan_keypad_mac_, mac.size()) == 0;
      family = static_cast<KeypadFamily>(this->battery_scan_keypad_family_);
    } else {
      // Keypad linked before the MAC was persisted: adopt the first advert
      // matching a known keypad signature (loop() persists it).
      const KeypadIdent ident = identify_keypad(sd.data(), sd.size());
      keypad_match = ident.is_keypad;
      family = ident.family;
    }

    if (keypad_match) {
      const int battery = parse_keypad_battery(
          family, sd.data(), sd.size(),
          reinterpret_cast<const uint8_t *>(mfr.data()), mfr.size());
      if (battery >= 0) {
        std::lock_guard<std::mutex> lk(this->rx_mutex_);
        this->keypad_battery_advert_value_ = battery;
        std::memcpy(this->keypad_battery_advert_mac_, mac.data(), mac.size());
        this->keypad_battery_advert_family_ = static_cast<uint8_t>(family);
        this->keypad_battery_advert_pending_ = true;
      }
    }
  }

  if (this->battery_scan_wants_lock_ && !this->lock_battery_scan_found_ &&
      std::memcmp(mac.data(), this->battery_scan_lock_mac_, mac.size()) == 0) {
    const std::vector<uint8_t> mfr_payload = switchbot_manufacturer_payload(adv);
    const int battery = parse_lock_battery(
        this->battery_scan_lock_model_, sd.data(), sd.size(),
        mfr_payload.data(), mfr_payload.size());
    if (battery >= 0) {
      std::lock_guard<std::mutex> lk(this->rx_mutex_);
      this->lock_battery_advert_value_ = battery;
      this->lock_battery_advert_pending_ = true;
    }
  }
}

// ---------------------------------------------------------------------------
// Battery advertisement scan
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::apply_pending_keypad_battery_() {
  int value;
  uint8_t mac[6];
  uint8_t family;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->keypad_battery_advert_pending_) return;
    this->keypad_battery_advert_pending_ = false;
    value = this->keypad_battery_advert_value_;
    std::memcpy(mac, this->keypad_battery_advert_mac_, sizeof(mac));
    family = this->keypad_battery_advert_family_;
  }

  if (this->keypad_info_.valid == 0) {
    std::memcpy(this->keypad_info_.mac, mac, sizeof(this->keypad_info_.mac));
    this->keypad_info_.family = family;
    this->keypad_info_.valid = 1;
    this->save_and_sync_(this->keypad_info_pref_, &this->keypad_info_);
    ESP_LOGI(TAG, "Learned keypad MAC %02X:%02X:%02X:%02X:%02X:%02X from advertisement",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  }

  // Mark this target as satisfied; the window closes once every expected
  // target has reported.
  this->keypad_battery_scan_found_ = true;
  this->publish_battery_if_changed_(this->keypad_battery_level_sensor_, value,
                                    this->last_keypad_battery_, "Keypad");
}

void SwitchbotKeypadBridge::apply_pending_lock_battery_() {
  int value;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->lock_battery_advert_pending_) return;
    this->lock_battery_advert_pending_ = false;
    value = this->lock_battery_advert_value_;
  }

  this->lock_battery_scan_found_ = true;
  this->publish_battery_if_changed_(this->lock_battery_level_sensor_, value,
                                    this->last_lock_battery_, "Lock");
}

void SwitchbotKeypadBridge::maybe_finish_battery_scan_() {
  if (!this->battery_scan_active_.load(std::memory_order_acquire)) {
    return;
  }
  if (this->battery_scan_wants_keypad_ && !this->keypad_battery_scan_found_) {
    return;
  }
  if (this->battery_scan_wants_lock_ && !this->lock_battery_scan_found_) {
    return;
  }
  this->stop_battery_scan_();
  this->next_battery_scan_at_ = millis() + this->battery_scan_interval_ms_;
}

void SwitchbotKeypadBridge::stop_battery_scan_() {
  if (this->battery_scan_active_.exchange(false, std::memory_order_acq_rel)) {
    NimBLEScan *scan = NimBLEDevice::getScan();
    if (scan->isScanning()) {
      scan->stop();
    }
    scan->clearResults();
  }
  this->battery_scan_wants_keypad_ = false;
  this->battery_scan_wants_lock_ = false;
  this->keypad_battery_scan_found_ = false;
  this->lock_battery_scan_found_ = false;
  this->battery_scan_keypad_known_ = false;
  this->battery_scan_lock_model_ = PhysicalLockModel::UNKNOWN;
}

bool SwitchbotKeypadBridge::background_ble_busy_() const {
  return this->pairing_ui_.is_running() ||
         this->lock_relay_busy_.load(std::memory_order_relaxed) ||
         (this->server_ != nullptr && this->server_->getConnectedCount() > 0);
}

void SwitchbotKeypadBridge::clear_lock_battery_() {
  this->reset_battery_sensor_(this->lock_battery_level_sensor_,
                              this->last_lock_battery_);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
