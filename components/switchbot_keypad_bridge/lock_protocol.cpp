#include "lock_protocol.h"

#include <cstring>

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

// Plain-text command frames as decoded from the keypad. The state-poll
// constant is a 3-byte prefix because the trailing byte is a per-family
// model suffix (varies between keypad models).
constexpr uint8_t FRAME_LOCK[8]              = {0x0F, 0x4E, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t FRAME_ACTION[4]            = {0x0F, 0x4E, 0x01, 0x03};
constexpr uint8_t FRAME_STATE_POLL_PREFIX[3] = {0x0F, 0x4F, 0x81};
// Doorbell press (Keypad Vision). A short, distinct 2-byte opcode the keypad
// sends on the shared slot when its doorbell button is pressed.
constexpr uint8_t FRAME_DOORBELL[2]          = {0x01, 0x03};

// Unlock frame layout: [hdr(4) | method | marker(0x80) | index | ...]
constexpr size_t  UNLOCK_METHOD_OFFSET = 4;
constexpr size_t  UNLOCK_MARKER_OFFSET = 5;
constexpr size_t  UNLOCK_INDEX_OFFSET  = 6;
constexpr uint8_t UNLOCK_MARKER        = 0x80;
constexpr uint8_t UNLOCK_INDEX_BASE    = 0x0A;

}  // namespace

const char *unlock_method_name(UnlockMethod method) {
  switch (method) {
    case UnlockMethod::FINGERPRINT:
      return "fingerprint";
    case UnlockMethod::PIN:
      return "pin";
    case UnlockMethod::NFC:
      return "nfc";
    case UnlockMethod::FACE:
      return "face";
    case UnlockMethod::PALM:
      return "palm";
    default:
      return "unknown";
  }
}

DecodedCommand decode_lock_command(const uint8_t *plaintext, size_t length) {
  DecodedCommand out;

  if (length == sizeof(FRAME_LOCK) && std::memcmp(plaintext, FRAME_LOCK, sizeof(FRAME_LOCK)) == 0) {
    out.type = CommandType::LOCK;
    return out;
  }
  if (length == 4 &&
      std::memcmp(plaintext, FRAME_STATE_POLL_PREFIX, sizeof(FRAME_STATE_POLL_PREFIX)) == 0) {
    out.type = CommandType::STATE_POLL;
    return out;
  }
  if (length == sizeof(FRAME_DOORBELL) &&
      std::memcmp(plaintext, FRAME_DOORBELL, sizeof(FRAME_DOORBELL)) == 0) {
    out.type = CommandType::DOORBELL;
    return out;
  }
  if (length >= 8 && std::memcmp(plaintext, FRAME_ACTION, sizeof(FRAME_ACTION)) == 0 &&
      plaintext[UNLOCK_MARKER_OFFSET] == UNLOCK_MARKER) {
    out.type = CommandType::UNLOCK;
    out.method = static_cast<UnlockMethod>(plaintext[UNLOCK_METHOD_OFFSET]);
    const uint8_t idx_byte = plaintext[UNLOCK_INDEX_OFFSET];
    // Original keypad: index encoded as 0x0A + zero-based slot. Vision: raw
    // zero-based byte (we only have a single capture with 0x00, so this is
    // a best-effort decode). Heuristic: if the byte ≥ 0x0A, treat as the
    // original biased encoding; otherwise pass it through as the raw index.
    out.credential_index = (idx_byte >= UNLOCK_INDEX_BASE)
                               ? static_cast<int16_t>(idx_byte - UNLOCK_INDEX_BASE)
                               : static_cast<int16_t>(idx_byte);
    return out;
  }

  return out;  // type stays CommandType::UNKNOWN
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
