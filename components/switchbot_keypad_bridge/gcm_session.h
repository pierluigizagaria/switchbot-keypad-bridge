#pragma once

#include <array>
#include <cstdint>
#include <string>
#include "lock_protocol.h"

namespace esphome {
namespace switchbot_keypad_bridge {

// Native Touch wire compatibility: two-byte tags and same-nonce replies.
// These protocol limitations also apply to this implementation.
class GcmSession {
 public:
  void begin(uint16_t connection, uint32_t now);
  bool process(const std::string &frame, uint16_t connection, uint32_t now,
               const std::array<uint8_t, 16> &key, bool locked);
  bool finish(uint16_t connection, uint32_t now, DecodedCommand &action);
  void reset();
  const std::string &response() const { return this->response_; }

 private:
  enum class Stage { HANDSHAKE, ACTION, POLL, COMPLETE, REJECTED };
  void reject(uint32_t now);
  static constexpr uint32_t TIMEOUT_MS = 10000;
  static constexpr uint32_t FAILURE_WINDOW_MS = 60000;
  static constexpr uint8_t FAILURE_LIMIT = 3;
  bool connected_{false};
  uint16_t connection_{0};
  uint32_t started_{0};
  uint32_t failures_since_{0};
  uint8_t failures_{0};
  uint8_t polls_{0};
  uint8_t slot_{0};
  Stage stage_{Stage::HANDSHAKE};
  std::array<uint8_t, 20> handshake_{};
  std::array<uint8_t, 12> nonce_{};
  std::string last_request_;
  std::string response_;
  DecodedCommand action_{};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
