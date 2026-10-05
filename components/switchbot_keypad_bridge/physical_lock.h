#pragma once

#include "nimble_compat.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

enum class PhysicalLockModel : uint8_t {
  UNKNOWN = 0,
  LOCK,
  LOCK_LITE,
  LOCK_PRO,
  LOCK_ULTRA,
  LOCK_VISION,
  LOCK_VISION_PRO,
  LOCK_PRO_WIFI,
};

const char *physical_lock_model_str(PhysicalLockModel model);
PhysicalLockModel physical_lock_model_from_api_type(const std::string &device_type);
bool is_supported_physical_lock_type(const std::string &device_type);

class PhysicalLockClient {
 public:
  PhysicalLockClient();
  ~PhysicalLockClient();
  PhysicalLockClient(const PhysicalLockClient &) = delete;
  PhysicalLockClient &operator=(const PhysicalLockClient &) = delete;

  // Route the locks' reply notifications to PhysicalLockClient. Call once,
  // right after NimBLEDevice::init() and before any BLE activity: NimBLE's
  // init clears the listener list, and the host walks that list unlocked.
  static bool install_reply_listener();

  struct Config {
    std::string mac;
    PhysicalLockModel model{PhysicalLockModel::UNKNOWN};
    uint8_t key_id{0};
    std::array<uint8_t, 16> key{};
  };

  // Coarse progress of one encrypted exchange, reported through the optional
  // callback below. Callers map these phases to their own user-facing steps.
  enum class Phase : uint8_t {
    SCAN = 0,
    CONNECT,
    DISCOVER,
    SESSION,
    COMMAND,
  };
  using ProgressCallback = std::function<void(Phase)>;
  using CommandProgressCallback = std::function<void(size_t command_index)>;
  using ResponseCallback = std::function<void(const std::vector<uint8_t> &response)>;

  // Verify that the configured key/slot can open an encrypted BLE session and
  // return a plausible lock-info payload.
  bool verify(const Config &config, std::string &error_out,
              const ProgressCallback &progress = nullptr);

  // Send one SwitchBot plaintext command body (the bytes after the leading
  // 0x57 command marker) to the physical lock and return the decrypted notify
  // payload from the lock. The caller provides the key/slot for this session.
  bool send_plaintext(const Config &config, const uint8_t *plaintext,
                      size_t plaintext_len, std::vector<uint8_t> &response_plaintext,
                      std::string &error_out,
                      const ProgressCallback &progress = nullptr,
                      const ResponseCallback &response_callback = nullptr);

  // Held link: open() connects and negotiates the encryption session once;
  // each send() then costs a single round trip; close() disconnects. Lets the
  // bridge prepare the lock link while the keypad is still reading a
  // credential. open() closes any link already held.
  bool open(const Config &config, std::string &error_out,
            const ProgressCallback &progress = nullptr);
  bool is_open() const { return this->held_open_; }
  uint8_t open_key_id() const { return this->held_config_.key_id; }
  bool send(const uint8_t *plaintext, size_t plaintext_len,
            std::vector<uint8_t> &response_plaintext, std::string &error_out);
  void close();

  // Send a short provisioning sequence over one encrypted session. This
  // mirrors the official keypad/lock binding flow where several 0F 20 ...
  // writes share the same IV.
  bool send_plaintext_sequence(const Config &config,
                               const std::vector<std::vector<uint8_t>> &commands,
                               std::vector<std::vector<uint8_t>> &responses,
                               std::string &error_out,
                               const ProgressCallback &progress = nullptr,
                               const ResponseCallback &response_callback = nullptr);

  // Provision the keypad/lock shared key with the lock's cloud credential,
  // then verify the freshly-written shared slot on the same BLE connection.
  bool provision_and_verify_shared_key(
      const Config &provisioning_config,
      const std::vector<std::vector<uint8_t>> &provision_commands,
      std::vector<std::vector<uint8_t>> &provision_responses,
      const Config &shared_config,
      std::string &error_out,
      const ProgressCallback &provision_progress = nullptr,
      const CommandProgressCallback &provision_command_progress = nullptr,
      const ProgressCallback &verify_progress = nullptr);

 private:
  enum class CryptoMode : uint8_t { CTR, GCM };

  struct Session {
    CryptoMode mode{CryptoMode::CTR};
    std::array<uint8_t, 16> ctr_iv{};
    std::array<uint8_t, 12> gcm_iv{};
  };

  // GATT handles of the lock's SwitchBot service: where commands are
  // written, where replies arrive, and the switch that enables reply
  // notifications. Filled by one discovery and reused on later connections
  // to the same lock, so a relay skips the ~0.4-0.5 s service discovery.
  struct GattHandles {
    uint16_t rx{0};
    uint16_t tx{0};
    uint16_t cccd{0};
    bool valid() const { return this->rx != 0 && this->tx != 0 && this->cccd != 0; }
  };

  // Receives the lock's reply notifications for one link (defined in the
  // .cpp; fed by a global NimBLE GAP listener, since links driven by cached
  // handles have no discovered characteristic to subscribe through).
  class ReplyChannel;

  // One open link to the lock and the handles it is driven through.
  struct Link {
    NimBLEClient *client{nullptr};
    GattHandles handles;
    bool from_cache{false};
  };

  bool connect_(const Config &config, Link &link, std::string &error_out,
                const ProgressCallback &progress);
  bool discover_handles_(Link &link, std::string &error_out);
  // Enable reply notifications and negotiate the encryption session.
  bool open_session_(const Config &config, const Link &link, ReplyChannel &replies,
                     Session &session, std::string &error_out);
  // Like open_session_(), but when the link runs on cached handles and the
  // lock rejects them, forget the cache, rediscover on the same link and
  // retry once.
  bool open_session_with_fallback_(const Config &config, Link &link,
                                   ReplyChannel &replies, Session &session,
                                   std::string &error_out);
  // Encrypt one command, send it and decrypt the lock's reply.
  bool exchange_(const Config &config, const Session &session, const Link &link,
                 ReplyChannel &replies, const std::vector<uint8_t> &command,
                 std::vector<uint8_t> &response, std::string &error_out);
  void close_(Link &link);
  bool parse_session_response_(const std::string &wire, Session &session,
                               std::string &error_out);
  bool send_encrypted_(const Config &config, const Session &session,
                       const Link &link, const uint8_t *plaintext,
                       size_t plaintext_len, std::string &error_out);
  bool decrypt_notify_(const Config &config, const Session &session,
                       const std::string &wire, std::vector<uint8_t> &out,
                       std::string &error_out);

  // Last advertisement address seen for cached_mac_, including its BLE
  // address type. Lets follow-up connects skip the ~2.5 s discovery scan —
  // the dominant cost of a relay round-trip. Invalidated when a connect
  // through it fails (the next attempt re-scans).
  NimBLEAddress cached_addr_{};
  std::string   cached_mac_;
  // Handles discovered on cached_mac_. RAM only: the first relay after a
  // boot discovers once. Cleared whenever the lock rejects them.
  GattHandles   cached_handles_{};

  // State of the link held between open() and close().
  Config held_config_{};
  Link held_link_{};
  Session held_session_{};
  std::unique_ptr<ReplyChannel> held_replies_;
  bool held_open_{false};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
