#pragma once

#include <psa/crypto.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <mutex>
#include <vector>

#include "esphome/components/button/button.h"
#include "esphome/components/event/event.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/automation.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/core/helpers.h"
#include "esphome/core/preferences.h"

#include "keypad_advert.h"
#include "lock_advert.h"
#include "lock_protocol.h"
#include "lock_session.h"
#include "nimble_compat.h"
#include "pairing_ui.h"
#include "physical_lock.h"

namespace esphome {
namespace switchbot_keypad_bridge {

// Upper bound (including the trailing NUL) on the persisted keypad name.
constexpr size_t KEYPAD_NAME_MAX = 48;

// The protocol layers live next door: lock_protocol.h decodes plaintext
// frames, lock_session.h owns the encrypted-session state machine (IV,
// anti-replay, transport crypto). This component is the NimBLE transport
// and the ESPHome-facing business logic on top of them.

// ── Concurrency model ───────────────────────────────────────────────────────
// Five execution contexts touch this component. The rule of thumb: only the
// main task acts; every other context hands data over and returns.
//
//   1. ESPHome main task — setup()/loop() and everything they call. The only
//      context that publishes entities, writes NVS, or mutates session and
//      battery-scan state.
//   2. NimBLE host task — server/characteristic callbacks and the battery
//      scan callback. They only enqueue: connect/disconnect/RX frames into
//      rx_queue_, keypad battery adverts into the keypad_battery_advert_* fields — both
//      under rx_mutex_, both drained by loop().
//   3. HTTP-server task (setup wizard) — handles requests, starts keypad
//      pairing / lock-link jobs and reports Status snapshots. It does not
//      publish entities or write NVS.
//   4. Pairing/linking FreeRTOS tasks ("kp-pair", "lock-link") — owned by
//      their job classes, which expose progress snapshots under their own
//      mutexes. PairingUi::poll_jobs() observes completion from loop().
//   5. Relay FreeRTOS task ("lock-relay") — forwards one keypad payload to
//      the physical lock and posts only the relay outcome through pending_relay_*.
class SwitchbotKeypadBridge : public Component {
  SUB_TEXT_SENSOR(keypad)
  SUB_TEXT_SENSOR(linked_lock)
  SUB_SENSOR(keypad_battery_level)
  SUB_SENSOR(lock_battery_level)

 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void set_keypad_event(event::Event *ev) { this->keypad_event_ = ev; }
  void set_pairing_ui_html(const uint8_t *html, size_t len) {
    this->pairing_ui_.set_html(html, len);
  }
  void set_battery_scan_interval(uint32_t ms) { this->battery_scan_interval_ms_ = ms; }

  bool is_pairing_active() const { return this->pairing_ui_.is_running(); }

  // Forgets the linked keypad and lock, rotates the shared key in place and
  // re-opens the setup wizard — no reboot. Invoked by ResetButton.
  void reset_pairing();

  // Sets the state reported on the keypad's next state poll. This lets an
  // external lock or door controller keep the emulated lock state in sync.
  // ESPHome actions run on the main task, so mutating lock_state_ here follows
  // the component's concurrency model.
  void set_lock_state(bool locked) {
    this->lock_state_ = locked ? LockState::LOCKED : LockState::UNLOCKED;
  }

  void add_on_lock_callback(std::function<void()> &&callback) {
    this->on_lock_callbacks_.add(std::move(callback));
  }
  void add_on_unlock_callback(std::function<void(std::string, int)> &&callback) {
    this->on_unlock_callbacks_.add(std::move(callback));
  }
  void add_on_doorbell_callback(std::function<void()> &&callback) {
    this->on_doorbell_callbacks_.add(std::move(callback));
  }

 protected:
  class ServerCallbacks;
  class RxCharCallbacks;
  class BatteryScanCallbacks;
  friend class ServerCallbacks;
  friend class RxCharCallbacks;
  friend class BatteryScanCallbacks;

  enum class LockState : uint8_t {
    LOCKED = 0x81,
    UNLOCKED = 0x91,
  };

  // Identity of the linked keypad, persisted to NVS at pairing time so the
  // battery scan can match its advertisement after a reboot. `valid == 0`
  // for keypads linked before this field existed — the scan then learns the
  // MAC from the first recognised keypad advert and persists it.
  struct KeypadInfo {
    uint8_t mac[6]{};   // big-endian, as printed
    uint8_t family{0};  // KeypadFamily
    uint8_t valid{0};
  };

  static constexpr size_t LOCK_NAME_MAX = 48;
  struct LinkedLockInfo {
    uint8_t mac[6]{};
    // Kept for NVS layout compatibility with early relay builds that stored
    // secret lock bytes here. It is zeroed on load/save and never used for
    // relay.
    uint8_t reserved[16]{};
    uint8_t slot_id{0};
    uint8_t model{0};  // PhysicalLockModel
    uint8_t valid{0};
    char name[LOCK_NAME_MAX]{};
  };

  // ----- Configuration / setup -----------------------------------------------

  // Generates a fresh AES-128 session key into shared_key_ and persists it
  // to NVS — the one place keys are created (first boot and reset_pairing()).
  void create_shared_key_();
  // (Re-)imports shared_key_ into the PSA crypto slot, replacing any handle
  // imported earlier. Lets reset_pairing() re-key the live session without a reboot.
  bool import_aes_key_();

  bool prepare_keys_();
  bool prepare_ble_();

  // ----- BLE write handling --------------------------------------------------

  // Validation, decryption and decoding live in LockSession; the bridge
  // dispatches the resulting Action and owns the business logic.
  void on_rx_frame_(const std::string &frame);

  void handle_command_(const FrameHeader &header, const DecodedCommand &command);
  void handle_state_poll_(const FrameHeader &header);
  // Builds the keypad-family reply for a command. Linked-lock mode still
  // answers the keypad locally; the physical relay runs independently.
  void send_local_response_(const FrameHeader &header, const DecodedCommand &command);
  // Mirrors the just-decrypted keypad payload onto the physical lock from a
  // one-shot background task. The keypad is never answered from this path;
  // relay completion is logged only.
  bool relay_to_lock_async_(const FrameHeader &header, const DecodedCommand &command);
  PhysicalLockClient::Config physical_lock_config_(uint8_t slot_id) const;

  // ----- Transport helpers ---------------------------------------------------

  void send_ack_(const FrameHeader &header);
  void send_encrypted_response_(const FrameHeader &header, const uint8_t *plaintext, size_t length);
  void notify_(const uint8_t *data, size_t length);

  // ----- Eventing ------------------------------------------------------------

  void publish_lock_();
  void publish_unlock_(UnlockMethod method, int index);
  void publish_doorbell_();
  void publish_linked_lock_();

  // ----- Battery refresh (advertisement scan) --------------------------------

  // Keypad and physical lock battery levels are read from BLE advertisements.
  // A short active scan can refresh both sensors and closes early once every
  // configured target has been seen.
  void maybe_start_battery_scan_();
  void maybe_finish_battery_scan_();
  void stop_battery_scan_();
  void apply_pending_keypad_battery_();
  void apply_pending_lock_battery_();
  // Runs on the NimBLE host task — parses the advert and queues the result.
  void handle_battery_advert_(const NimBLEAdvertisedDevice *adv);

  // ----- Battery helpers -----------------------------------------------------

  void clear_lock_battery_();
  bool background_ble_busy_() const;
  void save_and_sync_(ESPPreferenceObject &pref, const KeypadInfo *value);
  void save_and_sync_(ESPPreferenceObject &pref, const LinkedLockInfo *value);
  void publish_text_or_unlinked_(text_sensor::TextSensor *sensor, const char *value);
  void publish_battery_if_changed_(sensor::Sensor *sensor, int value, int &last, const char *label);
  void reset_battery_sensor_(sensor::Sensor *sensor, int &last);

  // ----- BLE handles ---------------------------------------------------------

  NimBLEServer *server_{nullptr};
  NimBLECharacteristic *tx_characteristic_{nullptr};

  // ----- Thread-safe event queueing from NimBLE callbacks --------------------

  struct QueuedEvent {
    enum Type { CONNECT, DISCONNECT, RX } type;
    std::string frame;
  };

  std::mutex rx_mutex_;
  std::vector<QueuedEvent> rx_queue_;

  void push_connect_();
  void push_disconnect_();
  void push_rx_(const std::string &frame);

  // ----- On-device setup wizard ----------------------------------------------

  PairingUi pairing_ui_{};

  void apply_pending_pairing_();
  void apply_pending_lock_link_();
  void apply_pending_lock_relay_();

  // A finished pairing/link is observed by PairingUi::poll_jobs() from loop().
  // The callback copies the completed job into these pending fields, then the
  // apply block below publishes entities and writes NVS in one place.
  std::atomic<bool> pending_pair_apply_{false};
  std::string pending_keypad_name_;
  std::string pending_keypad_mac_;
  KeypadFamily pending_keypad_family_{KeypadFamily::ORIGINAL};

  std::atomic<bool> pending_lock_apply_{false};
  std::string pending_lock_name_;
  std::string pending_lock_mac_;
  PhysicalLockModel pending_lock_model_{PhysicalLockModel::UNKNOWN};
  uint8_t pending_lock_slot_id_{0};

  // ----- ESPHome wiring ------------------------------------------------------

  event::Event *keypad_event_{nullptr};
  CallbackManager<void()> on_lock_callbacks_{};
  CallbackManager<void(std::string, int)> on_unlock_callbacks_{};
  CallbackManager<void()> on_doorbell_callbacks_{};

  // ----- User configuration --------------------------------------------------

  // 16-byte AES-128 session key. Generated on first boot, persisted in
  // NVS, rotated by reset_pairing(). Never part of the YAML config.
  std::array<uint8_t, 16> shared_key_{};
  ESPPreferenceObject shared_key_pref_;
  ESPPreferenceObject keypad_name_pref_;
  ESPPreferenceObject linked_lock_pref_;

  // ----- Runtime state -------------------------------------------------------

  // PSA AES-CTR key handle. Imported once at setup so the per-frame crypto
  // path does not pay the cost (or risk the failure) of re-importing it.
  psa_key_id_t aes_key_handle_{PSA_KEY_ID_NULL};
  LockState lock_state_{LockState::LOCKED};

  // Keypad encrypted-session state (token slot, IV, anti-replay, transport
  // crypto). The IV may survive BLE reconnects when the keypad continues the
  // same logical session. Only ever touched from the main task.
  LockSession session_{};

  PhysicalLockClient physical_lock_client_{};
  LinkedLockInfo linked_lock_info_{};
  bool lock_linked_{false};
  // True while the relay task owns physical_lock_client_ and the central
  // role; battery scans defer to it.
  std::atomic<bool> lock_relay_busy_{false};
  // Relay outcome, written by the relay task and consumed by loop() for
  // logging only. Fields are stable while the flag is false→true (single
  // relay in flight, release/acquire pairing).
  std::atomic<bool> pending_relay_apply_{false};
  DecodedCommand relay_command_{};
  bool           relay_ok_{false};

  // ----- Keypad battery state --------------------------------------------------

  ESPPreferenceObject keypad_info_pref_;
  KeypadInfo keypad_info_{};
  bool keypad_paired_{false};

  uint32_t battery_scan_interval_ms_{15 * 60 * 1000};
  uint32_t next_battery_scan_at_{0};  // millis() deadline for the next scan
  // Written by loop(), read by the NimBLE scan callback as its "is this our
  // scan window?" gate — hence atomic.
  std::atomic<bool> battery_scan_active_{false};
  BatteryScanCallbacks *battery_scan_callbacks_{nullptr};
  std::atomic<bool> battery_scan_wants_keypad_{false};
  std::atomic<bool> battery_scan_wants_lock_{false};
  std::atomic<bool> keypad_battery_scan_found_{false};
  std::atomic<bool> lock_battery_scan_found_{false};
  std::atomic<bool> battery_scan_keypad_known_{false};
  uint8_t battery_scan_keypad_mac_[6]{};
  uint8_t battery_scan_keypad_family_{0};
  uint8_t battery_scan_lock_mac_[6]{};
  PhysicalLockModel battery_scan_lock_model_{PhysicalLockModel::UNKNOWN};
  int last_keypad_battery_{-1};  // last published value; -1 = nothing published yet
  int last_lock_battery_{-1};

  // Latest advert parsed by the NimBLE scan callback, handed to loop()
  // under rx_mutex_ (same pattern as the RX queue).
  bool keypad_battery_advert_pending_{false};
  int keypad_battery_advert_value_{-1};
  uint8_t keypad_battery_advert_mac_[6]{};
  uint8_t keypad_battery_advert_family_{0};
  bool lock_battery_advert_pending_{false};
  int lock_battery_advert_value_{-1};
};

// Home Assistant reset button: forgets keypad and lock, rotates the shared key
// and re-opens the setup wizard — all without a reboot.
class ResetButton : public button::Button, public Parented<SwitchbotKeypadBridge> {
 protected:
  void press_action() override;
};

// Home Assistant button that reports the emulated lock as locked. It does not
// operate a physical lock. Keypad Vision uses the reported state to re-arm
// passive face recognition after an unlock.
class ReportLockedButton : public button::Button,
                           public Parented<SwitchbotKeypadBridge> {
 protected:
  void press_action() override;
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
