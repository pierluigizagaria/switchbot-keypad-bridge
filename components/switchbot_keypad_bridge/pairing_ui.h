#pragma once

// Lightweight HTTP server that hosts the on-device pairing wizard.
//
// Endpoints:
//   GET  /                       → embedded HTML (single self-contained page)
//   POST /api/login              → {email,password} → {region} | 401
//   GET  /api/keypads            → [ {mac, name, model, online, rssi} ]
//   POST /api/pair               → {mac} → {job_id, labels: [step names]}
//   GET  /api/pair/status        → {step, total, message, done, error}
//
// The server uses ESP-IDF's `esp_http_server` (already pulled in by NimBLE
// and the ESP-IDF framework — no extra managed components needed).
// It binds to port 80 by default; if ESPHome's `web_server:` is also
// enabled the user must move one of the two onto a different port.

#include <esp_http_server.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "cloud_client.h"
#include "keypad_pairer.h"

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

  bool is_running() const { return this->server_ != nullptr; }

 private:
  // URI handler trampolines — esp_http_server takes a C function, so the
  // handlers are static and forward to the instance stored in
  // req->user_ctx (set to `this` at registration time).
  static esp_err_t handle_root_(httpd_req_t *req);
  static esp_err_t handle_login_(httpd_req_t *req);
  static esp_err_t handle_keypads_(httpd_req_t *req);
  static esp_err_t handle_pair_(httpd_req_t *req);
  static esp_err_t handle_pair_status_(httpd_req_t *req);

  static esp_err_t reply_json_(httpd_req_t *req, const char *json,
                               const char *status = "200 OK");
  static esp_err_t reply_error_(httpd_req_t *req, const char *status,
                                const std::string &message);
  static std::string read_body_(httpd_req_t *req);

  httpd_handle_t server_{nullptr};
  CloudClient    cloud_{};
  KeypadPairer   pairer_{};
  std::array<uint8_t, 16> shared_key_{};
  const uint8_t *html_{nullptr};
  size_t         html_len_{0};
  OnPairedCallback on_paired_cb_;
  // Identify the pairing this UI started. The success handler matches
  // Status::job_id against pairing_job_id_ before firing on_paired_cb_,
  // so a previous job's lingering SUCCESS can never apply the wrong
  // name. All three fields are touched only by the HTTP-server task.
  std::string    pairing_keypad_name_;
  std::string    pairing_job_id_;
  bool           success_notified_{false};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
