#pragma once

// Lightweight HTTP server that hosts the on-device setup wizard.
//
// Endpoints:
//   GET  /                       → embedded HTML (single self-contained page)
//   POST /api/login              → {email,password} → {region, keypad_paired,
//                                   lock_linked} | 401
//   GET  /api/keypads            → [ {mac, name, model, online, rssi} ]
//   POST /api/pair               → {mac} → {job_id, labels: [step names]}
//   GET  /api/pair/status        → {step, total, message, done, error}
//   GET  /api/locks              → [ {mac, name, model, online, rssi} ]
//   POST /api/lock/link          → {mac} → {job_id, labels: [step names]}
//   GET  /api/lock/link/status   → {step, total, message, done, error}
//
// The server uses ESP-IDF's `esp_http_server`, enabled by this component's
// ESPHome codegen. It binds to port 80 by default.

#include <esp_http_server.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "cloud_client.h"
#include "keypad_advert.h"
#include "keypad_pairer.h"
#include "lock_linker.h"
#include "physical_lock.h"

namespace esphome {
namespace switchbot_keypad_bridge {

class PairingUi {
 public:
  // start() boots the HTTP server and registers all URI handlers. Returns
  // false on init failure (port conflict, OOM, ...). Idempotent: calling
  // it again on an already-running server is a no-op.
  bool start(uint16_t port = 80);

  // stop() releases the server handle. Safe to call when not started.
  void stop();

  // The bridge's 16-byte AES session key — injected into the keypad's lock
  // slot during pairing.
  void set_shared_key(const std::array<uint8_t, 16> &key) { this->shared_key_ = key; }
  void set_keypad_paired(bool paired) { this->keypad_paired_.store(paired); }
  void set_keypad_family(KeypadFamily family) {
    this->keypad_family_.store(static_cast<uint8_t>(family));
  }
  void set_lock_linked(bool linked) { this->lock_linked_.store(linked); }

  // The embedded UI page, gzip-compressed and baked into flash by codegen
  // (see __init__.py); served verbatim with Content-Encoding: gzip.
  // Not NUL-terminated, so the length is carried alongside the pointer.
  void set_html(const uint8_t *html, size_t len) {
    this->html_ = html;
    this->html_len_ = len;
  }

  // Called once after a successful pairing with the keypad's display name,
  // pretty MAC and protocol family (the latter two feed the battery scan).
  using OnPairedCallback = std::function<void(
      const std::string &name, const std::string &mac, KeypadFamily family)>;
  void set_on_paired_callback(OnPairedCallback cb) {
    this->on_paired_cb_ = std::move(cb);
  }

  using OnLockLinkedCallback = std::function<void(
      const std::string &name, const std::string &mac, PhysicalLockModel model,
      uint8_t slot_id)>;
  void set_on_lock_linked_callback(OnLockLinkedCallback cb) {
    this->on_lock_linked_cb_ = std::move(cb);
  }

  bool is_running() const { return this->server_ != nullptr; }

  // Idle shutdown: stops the server once no request has arrived for
  // `timeout_ms`. Refuses to fire while a pairing or lock-link job is still
  // RUNNING, so closing the browser mid-job can never kill the server under
  // an in-flight BLE handshake.
  bool stop_if_idle(uint32_t now_ms, uint32_t timeout_ms = 5 * 60 * 1000);

  // Fires the one-shot success callbacks for both background jobs. Called
  // from the bridge's loop() so a pairing/link that completes after the
  // browser disappeared is still applied — the HTTP status handlers are pure
  // reporters and never fire callbacks.
  void poll_jobs();

 private:
  // URI handler trampolines — esp_http_server takes a C function, so the
  // handlers are static and forward to the instance stored in
  // req->user_ctx (set to `this` at registration time).
  static esp_err_t handle_root_(httpd_req_t *req);
  static esp_err_t handle_login_(httpd_req_t *req);
  static esp_err_t handle_keypads_(httpd_req_t *req);
  static esp_err_t handle_pair_(httpd_req_t *req);
  static esp_err_t handle_pair_status_(httpd_req_t *req);
  static esp_err_t handle_locks_(httpd_req_t *req);
  static esp_err_t handle_lock_link_(httpd_req_t *req);
  static esp_err_t handle_lock_link_status_(httpd_req_t *req);

  static esp_err_t reply_json_(httpd_req_t *req, const char *json,
                               const char *status = "200 OK");
  static esp_err_t reply_error_(httpd_req_t *req, const char *status,
                                const std::string &message);
  static std::string read_body_(httpd_req_t *req);
  void touch_activity_();

  httpd_handle_t server_{nullptr};
  CloudClient    cloud_{};
  KeypadPairer   pairer_{};
  LockLinker     linker_{};
  std::array<uint8_t, 16> shared_key_{};
  std::atomic<uint8_t> keypad_family_{static_cast<uint8_t>(KeypadFamily::ORIGINAL)};
  const uint8_t *html_{nullptr};
  size_t         html_len_{0};
  OnPairedCallback on_paired_cb_;
  OnLockLinkedCallback on_lock_linked_cb_;
  std::atomic<bool> keypad_paired_{false};
  std::atomic<bool> lock_linked_{false};
  std::atomic<uint32_t> last_activity_ms_{0};
  // Identify the jobs this UI started. poll_jobs() matches Status::job_id
  // against the stored id before firing the one-shot callbacks, so a previous
  // job's lingering SUCCESS can never apply the wrong device. Job starts run
  // on the HTTP-server task while poll_jobs() runs on the main loop — hence
  // the mutex.
  std::mutex     jobs_mu_;
  std::string    pairing_keypad_name_;
  std::string    pairing_job_id_;
  bool           success_notified_{false};
  std::string    link_job_id_;
  bool           link_notified_{false};

  // Keypads identified from their BLE advertisement, keyed by pretty MAC. A
  // keypad's model signature rides in the 0xFD3D service data, which for the
  // Keypad Vision only arrives in the (intermittently received) scan response.
  // Caching every positive identification keeps such a keypad listed on later
  // scans where its service data was missed, as long as it's still in range.
  std::map<std::string, KeypadIdent> identified_keypads_;
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
