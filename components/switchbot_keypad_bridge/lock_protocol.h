#pragma once

// SwitchBot keypad command decoding — the pure "what did the keypad ask for"
// layer. It takes the already-decrypted plaintext bytes of a frame and
// classifies them into a command, with no NimBLE, crypto or transport
// dependencies. This is the half of the protocol worth reasoning about (and
// testing) in isolation; the encrypted transport that feeds it lives in the
// bridge component.

#include <cstddef>
#include <cstdint>

namespace esphome {
namespace switchbot_keypad_bridge {

// How a credential presented itself at the keypad. Values are the method byte
// the keypad sends inside an unlock frame.
enum class UnlockMethod : uint8_t {
  UNKNOWN = 0x00,
  PIN = 0x04,
  NFC = 0x08,
  FINGERPRINT = 0x0C,
  FACE = 0x18,
  // Palm/hand-vein recognition, confirmed by capturing the raw decrypted
  // unlock frame on a Keypad Vision Pro (the method byte was previously
  // unmapped and fell back to UNKNOWN/"unknown").
  PALM = 0x20,
};

const char *unlock_method_name(UnlockMethod method);

// The command a decrypted keypad frame represents. UNKNOWN means the bytes
// matched no known frame; the bridge may still relay the raw plaintext to a
// linked physical lock.
enum class CommandType : uint8_t {
  UNKNOWN,
  LOCK,
  UNLOCK,
  STATE_POLL,
  DOORBELL,
};

struct DecodedCommand {
  CommandType type{CommandType::UNKNOWN};
  UnlockMethod method{UnlockMethod::UNKNOWN};
  int16_t credential_index{-1};
};

// Classify a decrypted plaintext frame. Returns a command with
// type == CommandType::UNKNOWN when the bytes match no known frame.
DecodedCommand decode_lock_command(const uint8_t *plaintext, size_t length);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
