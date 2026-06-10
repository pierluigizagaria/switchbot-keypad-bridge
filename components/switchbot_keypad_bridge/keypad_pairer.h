#pragma once

// Background task that drives a single keypad↔ESP pairing session.
//
// Runs the pairing handshake step by step:
//   1. Connect as BLE central to the keypad
//   2. Subscribe to its TX characteristic
//   3. Negotiate a session IV (`57 00 00 00 0F 21 03 <key_id>`)
//   4. Send 7-8 K14-encrypted commands that open the lock slot,
//      inject our shared_token, and switch the keypad's lock target
//      to the ESP's BLE address
//   5. Disconnect
//
// Spawned once per pairing attempt; the HTTP handler polls `status()`
// at ~2 Hz from the UI's `/api/pair/status`.

#include "nimble_compat.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "keypad_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

class KeypadPairer {
 public:
  enum class State : uint8_t {
    IDLE,
    RUNNING,
    SUCCESS,
    FAILED,
  };

  // Snapshot of the pairer's progress, safe to copy across threads.
  struct Status {
    State       state{State::IDLE};
    uint8_t     step{0};       // 0-based index of the step currently in flight
    uint8_t     total{0};      // total number of steps; 0 before start
    std::string message;       // human-readable status of the current step
    std::string error;         // populated when state == FAILED
    std::string job_id;        // matches the value returned by start()
    // Identity of the keypad just paired, valid only when state == SUCCESS.
    // The family comes from the live advertisement read during discovery.
    std::string keypad_mac;    // pretty form, e.g. "B0:E9:FE:..."
    KeypadFamily family{KeypadFamily::ORIGINAL};
  };

  // Arguments for a single pairing attempt. The protocol family is NOT passed
  // in — the pairer reads it from the keypad's live BLE advertisement during
  // discovery (keypad_advert.h), which is the single source of truth.
  struct Request {
    std::string                  keypad_mac;       // pretty form, e.g. "B0:E9:FE:..."
    int                          key_id{0};        // 0x88 / 0xC6 / ... from cloud
    std::vector<uint8_t>         key;              // 16-byte AES-CTR key from cloud
    std::array<uint8_t, 16>      shared_token{};   // the random key we inject
    std::array<uint8_t, 6>       esp_mac{};        // our BLE peripheral address
  };

  // Spawns the pairing task and returns a job id. If a job is already
  // running this returns an empty string and leaves the current job
  // untouched — only one pairing can be in flight at a time.
  std::string start(Request req);

  // The user-facing label of each pairing step, in order. The wizard builds
  // its progress stepper from these (returned by /api/pair), so the pairer
  // is the single source of truth for step count, order and wording.
  static uint8_t step_count();
  static const char *step_label(uint8_t step);

  // Atomic snapshot of progress. Suitable for polling from any thread.
  Status status() const;

 private:
  void execute_(Request &req);

  // Step helpers (push step number + message, log, return immediately).
  void set_step_(uint8_t step, const char *msg);
  void set_running_(uint8_t total, const std::string &job_id);
  void set_success_(const std::string &keypad_mac, KeypadFamily family);
  void set_failed_(const std::string &err);

  // BLE notification sink: we look for the 20-byte session-IV response
  // (`01 00 00 00 <IV[16]>`) and stash the IV. Everything else just
  // releases the ACK semaphore so `send_command_` can move on.
  void on_notify_(const uint8_t *data, size_t length);

  // One encrypted BLE write + best-effort ACK wait. plaintext is
  // encrypted in place with AES-128-CTR using `key_` and `iv_`.
  bool send_command_(NimBLERemoteCharacteristic *rx,
                     const uint8_t *plaintext, size_t plaintext_len);

  // ----- Shared state (read by status(), written by the task) -----
  mutable std::mutex   mu_;
  Status               status_{};

  // ----- Task / sync primitives -----
  TaskHandle_t         task_handle_{nullptr};
  SemaphoreHandle_t    ack_sem_{nullptr};  // released on every TX notification

  // ----- Per-job state, only touched by the task -----
  std::vector<uint8_t> key_;                // copy of req.key
  uint8_t              key_id_{0};
  std::array<uint8_t, 16> iv_{};            // session IV; valid once iv_received_
  std::atomic<bool>    iv_received_{false};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
