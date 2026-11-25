#include "gcm_session.h"

#include <algorithm>
#include <cstring>
#include <esp_random.h>
#include <mbedtls/platform_util.h>
#include "aes_ctr.h"

namespace esphome {
namespace switchbot_keypad_bridge {
namespace {
bool increment(std::array<uint8_t, 12> &nonce) {
  for (int i = 11; i >= 0; --i) {
    if (++nonce[static_cast<size_t>(i)] != 0) return true;
  }
  return false;
}
}  // namespace

void GcmSession::reset() {
  this->connected_ = false;
  this->stage_ = Stage::HANDSHAKE;
  this->polls_ = 0;
  this->slot_ = 0;
  this->action_ = {};
  this->last_request_.clear();
  this->response_.clear();
  this->handshake_.fill(0);
  this->nonce_.fill(0);
}

void GcmSession::begin(uint16_t connection, uint32_t now) {
  if (this->connected_) return;
  this->reset();
  this->connected_ = true;
  this->connection_ = connection;
  this->started_ = now;
}

void GcmSession::reject(uint32_t now) {
  this->stage_ = Stage::REJECTED;
  this->action_ = {};
  if (this->failures_ == 0) this->failures_since_ = now;
  if (this->failures_ < FAILURE_LIMIT) ++this->failures_;
}

bool GcmSession::process(const std::string &frame, uint16_t connection, uint32_t now,
                         const std::array<uint8_t, 16> &key, bool locked) {
  if (this->failures_ && now - this->failures_since_ >= FAILURE_WINDOW_MS) this->failures_ = 0;
  if (!this->connected_ || connection != this->connection_ ||
      now - this->started_ >= TIMEOUT_MS || this->stage_ == Stage::REJECTED) return false;
  if (this->failures_ >= FAILURE_LIMIT) {
    this->stage_ = Stage::REJECTED;
    return false;
  }
  const auto *wire = reinterpret_cast<const uint8_t *>(frame.data());
  const uint8_t opening[] = {0x57, 0, 0, 0, 0x0F, 0x21, 0x03};
  if (frame.size() == 8 && std::memcmp(wire, opening, sizeof(opening)) == 0) {
    // The project has two protocol families. Accept both known slots;
    // application commands on untested models still need community testing.
    if (wire[7] != 0x88 && wire[7] != 0xC6) {
      this->reject(now);
      return false;
    }
    if (this->stage_ == Stage::HANDSHAKE) {
      this->slot_ = wire[7];
      this->handshake_ = {0x01, 0, 0x01, 0};
      esp_fill_random(this->nonce_.data(), this->nonce_.size());
      std::copy(this->nonce_.begin(), this->nonce_.end(), this->handshake_.begin() + 4);
      this->stage_ = Stage::ACTION;
    } else if (this->stage_ != Stage::ACTION || !this->last_request_.empty() || wire[7] != this->slot_) {
      this->reject(now);
      return false;
    }
    this->response_.assign(reinterpret_cast<const char *>(this->handshake_.data()), this->handshake_.size());
    return true;
  }
  if (this->stage_ == Stage::HANDSHAKE || frame.size() < 4 || wire[0] != 0x57 || wire[1] != this->slot_) {
    this->reject(now);
    return false;
  }
  if (frame == this->last_request_) return true;
  const bool first = this->stage_ == Stage::ACTION;
  if (frame.size() != (first ? 12U : 8U) || this->polls_ >= 16) {
    this->reject(now);
    return false;
  }
  const uint8_t prefix[2] = {wire[2], wire[3]};
  uint8_t plain[8]{};
  const size_t length = frame.size() - 4;
  if (!aes_gcm_decrypt_verify_prefix(key.data(), this->nonce_.data(), wire + 4, plain, length, prefix)) {
    this->reject(now);
    return false;
  }
  const auto command = decode_lock_command(plain, length);
  mbedtls_platform_zeroize(plain, sizeof(plain));
  const bool unlock = command.type == CommandType::UNLOCK &&
      (command.method == UnlockMethod::FINGERPRINT || command.method == UnlockMethod::PIN ||
       command.method == UnlockMethod::NFC);
  if ((first && command.type != CommandType::LOCK && !unlock) ||
      (!first && command.type != CommandType::STATE_POLL)) {
    this->reject(now);
    return false;
  }
  auto next = this->nonce_;
  if (!increment(next)) {
    this->reject(now);
    return false;
  }
  const auto action = first ? command : this->action_;
  const bool lock = action.type == CommandType::LOCK;
  // Native action/state fields from verified captures. Mechanical telemetry
  // fields and byte 1 of the action ACK retain representative values.
  const uint8_t ack[] = {static_cast<uint8_t>(lock ? (locked ? 0x86 : 0x96) : 0x9E), 0xA4, 0x7F, 0x7F, 0};
  uint8_t state[] = {0x94, 0x08, 0x86, 0x56, 0, 0, 0, 0, 0x40, 0x09, 0x05, 0, 0, 0};
  if (lock) {
    state[0] = 0x86;
    state[8] = 0;
    state[9] = 0x7C;
    state[10] = 0x08;
  }
  const auto *body = first ? ack : state;
  const size_t body_size = first ? sizeof(ack) : sizeof(state);
  uint8_t reply[18] = {0x01, wire[1]};
  uint8_t tag[16];
  if (!aes_gcm_encrypt_raw_key(key.data(), this->nonce_.data(), body, reply + 4, body_size, tag)) {
    this->reject(now);
    return false;
  }
  reply[2] = tag[0];
  reply[3] = tag[1];
  this->response_.assign(reinterpret_cast<const char *>(reply), 4 + body_size);
  this->last_request_ = frame;
  this->nonce_ = next;
  this->action_ = action;
  this->stage_ = first ? Stage::POLL : Stage::COMPLETE;
  if (!first) ++this->polls_;
  return true;
}

bool GcmSession::finish(uint16_t connection, uint32_t now, DecodedCommand &action) {
  action = {};
  if (!this->connected_ || connection != this->connection_) return false;
  const bool complete = this->stage_ == Stage::COMPLETE && now - this->started_ < TIMEOUT_MS;
  if (complete) action = this->action_;
  this->reset();
  return complete;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
