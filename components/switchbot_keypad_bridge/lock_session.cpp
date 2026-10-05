#include "lock_session.h"

#include <cstring>

#include <esp_random.h>

#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "aes_ctr.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.session";

// Encrypted protocol framing.
constexpr uint8_t PROTOCOL_MAGIC = 0x57;
constexpr uint8_t VISION_KEY_SLOT = 0xC6;

// Session IV negotiation. Most keypads send this after connect; some reconnect
// and continue with the IV they already have.
// Shape: 57 00 00 00 0F 21 03 <key_id>
constexpr size_t SESSION_IV_REQ_MIN = 8;

constexpr size_t IV_RESPONSE_HEADER = 4;  // iv_response_ prefix before the IV bytes

}  // namespace

void LockSession::reset() {
  this->active_ = CryptoContext{};
  this->pending_ = CryptoContext{};
  this->retired_ = CryptoContext{};
  this->reset_transport();
}

void LockSession::reset_transport() {
  this->clear_transient_();
  this->retired_ = CryptoContext{};
  this->active_.late_action_allowed = false;
  this->active_.handoff_poll_seen = false;
}

void LockSession::clear_transient_() {
  this->plaintext_size_ = 0;
  this->header_ = FrameHeader{};
  this->command_ = DecodedCommand{};
  this->response_iv_valid_ = false;
}

LockSession::Action LockSession::process_frame(const std::string &frame) {
  // Never expose stale decoded bytes or a stale response IV after a dropped
  // frame. The bridge may relay plaintext asynchronously after COMMAND.
  this->clear_transient_();

  ESP_LOGV(TAG, "RX WIRE %zu bytes: %s", frame.size(),
           format_hex_pretty(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()).c_str());

  if (this->is_iv_request_(frame)) {
    // The IV request advertises which key_id the keypad will use for the
    // rest of the session (`57 00 00 00 0F 21 03 <key_id>`). Adapt to it —
    // Original/Touch uses 0x88, Vision/Vision Pro uses 0xC6.
    const uint8_t requested_slot = static_cast<uint8_t>(frame[7]);
    if (requested_slot != this->slot_id_) {
      ESP_LOGI(TAG, "Token slot: 0x%02X", requested_slot);
      // Crypto contexts are not bound to the key_id byte carried outside the
      // ciphertext. Treat a slot change as a hard session boundary so neither
      // an active, pending nor retired IV can be relabelled for the new slot.
      this->active_ = CryptoContext{};
      this->pending_ = CryptoContext{};
      this->retired_ = CryptoContext{};
      this->slot_id_ = requested_slot;
    }
    ESP_LOGD(TAG, "IV request");
    // Do not overwrite active_ yet. Vision-family keypads can send a delayed
    // state poll from the previous generation after requesting the next IV.
    this->ensure_pending_iv_();
    return Action::SEND_IV;
  }

  if (frame.size() <= HEADER_LEN ||
      static_cast<uint8_t>(frame[0]) != PROTOCOL_MAGIC) {
    ESP_LOGD(TAG, "Ignoring non-protocol frame (size=%zu)", frame.size());
    return Action::NONE;
  }

  this->header_ = FrameHeader{static_cast<uint8_t>(frame[1]), static_cast<uint8_t>(frame[2]),
                              static_cast<uint8_t>(frame[3])};

  if (this->header_.key_id != this->slot_id_) {
    ESP_LOGD(TAG, "Ignoring frame with unexpected key_id=0x%02X", this->header_.key_id);
    return Action::NONE;
  }

  // Refuse encrypted frames before any IV has been negotiated for this key.
  // BLE reconnects may preserve active_, but a fresh boot/reset must not
  // decrypt against a zero or unrelated IV.
  if (!this->active_.valid && !this->pending_.valid) {
    ESP_LOGW(TAG, "Dropping encrypted frame: no IV negotiated");
    return Action::NONE;
  }

  // The protocol echoes IV[0..1] as seq_a/seq_b. Prefer pending_ when the
  // keypad has switched, then active_, then the one short-lived predecessor
  // retained for the Fast Unlock race. Valid contexts always have distinct
  // seq pairs and pending_/retired_ never coexist.
  const bool uses_pending = this->seq_matches_(this->pending_, this->header_);
  const bool uses_active = this->seq_matches_(this->active_, this->header_);
  const bool uses_retired = this->seq_matches_(this->retired_, this->header_);
  if (!uses_pending && !uses_active && !uses_retired) {
    ESP_LOGW(TAG, "Dropping frame: seq_a/seq_b mismatch (cross-session replay?)");
    return Action::NONE;
  }

  // After pending_ was promoted by a poll, retired_ is eligible for exactly
  // the next valid encrypted frame. Seeing the current generation first is a
  // deterministic proof that the predecessor hand-off has ended.
  if (uses_active && this->retired_.valid) {
    ESP_LOGV(TAG, "Current IV observed; closing predecessor hand-off");
    this->retired_ = CryptoContext{};
  }
  CryptoContext &context = uses_pending ? this->pending_
                           : uses_active ? this->active_
                                         : this->retired_;

  const size_t ct_len = frame.size() - HEADER_LEN;
  if (ct_len > MAX_PAYLOAD) {
    ESP_LOGW(TAG, "Dropping frame with invalid payload length: %zu", ct_len);
    if (uses_retired) {
      this->retired_ = CryptoContext{};
    }
    return Action::NONE;
  }

  const uint8_t *ciphertext = reinterpret_cast<const uint8_t *>(frame.data() + HEADER_LEN);

  uint8_t plaintext[MAX_PAYLOAD];
  if (!this->xcrypt_(context.iv, ciphertext, ct_len, plaintext)) {
    if (uses_retired) {
      this->retired_ = CryptoContext{};
    }
    return Action::NONE;  // error already logged
  }

  ESP_LOGD(TAG, "RX %s", format_hex_pretty(plaintext, ct_len).c_str());

  this->command_ = decode_lock_command(plaintext, ct_len);

  // Fast Unlock on Vision periodically rotates the IV while an action can
  // already be in flight under the predecessor: a credential UNLOCK, or a
  // LOCK from the keypad's lock button (observed: Lock sent 0.7 s after an
  // IV request, before the keypad switched). Admit one such action before or
  // immediately after a state poll promotes pending_. LOCK only moves the
  // door to the safe state, so it is no riskier than the late UNLOCK. This
  // allowance is bounded only by protocol events: no wall-clock timeout is
  // involved.
  const bool uses_predecessor =
      uses_retired || (uses_active && this->pending_.valid);
  const bool has_known_unlock_method = unlock_method_index(this->command_.method) >= 0;
  const bool is_late_action =
      (this->command_.type == CommandType::UNLOCK && has_known_unlock_method) ||
      this->command_.type == CommandType::LOCK;

  // While pending_ is uncommitted, tolerate one already-in-flight poll under
  // active_. A second such poll proves the overlap has advanced without an
  // unlock and deterministically closes the allowance.
  if (uses_active && this->pending_.valid &&
      this->command_.type == CommandType::STATE_POLL &&
      context.late_action_allowed) {
    if (context.handoff_poll_seen) {
      context.late_action_allowed = false;
      ESP_LOGV(TAG, "Second predecessor poll closed hand-off allowance");
    } else {
      context.handoff_poll_seen = true;
    }
  }

  if (uses_predecessor && this->command_.type != CommandType::STATE_POLL) {
    // The first non-poll predecessor attempt always consumes the capability,
    // even when its command or replay status makes the frame inadmissible.
    const bool accept_late_action = is_late_action && context.late_action_allowed;
    context.late_action_allowed = false;
    if (!accept_late_action) {
      ESP_LOGW(TAG, "Dropping non-poll frame under superseded IV");
      this->command_ = DecodedCommand{};
      if (uses_retired) {
        this->retired_ = CryptoContext{};
      }
      return Action::NONE;
    }
  }

  if (this->command_.type == CommandType::UNKNOWN) {
    ESP_LOGW(TAG, "Dropping unsupported keypad command");
    if (uses_pending) {
      // Even an unsupported attempt under the new IV closes the older action
      // window. Do not execute or promote it, and do not leave a predecessor
      // capability open after seeing traffic from the next generation.
      this->active_.late_action_allowed = false;
      this->active_.handoff_poll_seen = false;
    }
    if (uses_retired) {
      this->retired_ = CryptoContext{};
    }
    return Action::NONE;
  }

  // DOORBELL is deliberately left out of the replay filter: under a fixed
  // session IV a second legitimate press in the same connection produces the
  // exact same ciphertext, and dropping it would swallow real rings. Worst
  // case for a replayed doorbell frame is a spurious chime; a repeated
  // lock/unlock changes security state, so those actions are deduplicated.
  if (this->command_.type == CommandType::LOCK || this->command_.type == CommandType::UNLOCK) {
    // Deduplicate the decoded action for the whole lifetime of its IV. A
    // different padding byte or payload length must not bypass the history.
    // The original credential byte avoids conflating two IDs through the
    // display-index heuristic. This is not authentication:
    // CTR still permits an attacker to forge a previously unseen action.
    if (this->is_replayed_action_(context, this->command_)) {
      ESP_LOGW(TAG, "Dropping repeated action within session");
      this->command_ = DecodedCommand{};
      if (uses_retired) {
        this->retired_ = CryptoContext{};
      }
      return Action::NONE;
    }
    this->record_action_(context, this->command_);
    if (uses_predecessor) {
      context.late_action_allowed = false;
      ESP_LOGI(TAG, "Accepted one late action under predecessor IV");
    }
  }

  std::memcpy(this->plaintext_.data(), plaintext, ct_len);
  this->plaintext_size_ = ct_len;
  this->response_iv_ = context.iv;
  this->response_iv_valid_ = true;

  if (uses_pending) {
    // Only a poll can race an older credential action. Any other supported
    // command under pending_ commits the new generation outright.
    const bool retain_predecessor =
        this->command_.type == CommandType::STATE_POLL && this->active_.valid &&
        this->active_.late_action_allowed;
    this->retired_ = retain_predecessor ? this->active_ : CryptoContext{};
    this->active_ = this->pending_;
    this->active_.late_action_allowed = false;
    this->active_.handoff_poll_seen = false;
    this->pending_ = CryptoContext{};
    ESP_LOGV(TAG, "Pending IV promoted");
  } else if (uses_retired) {
    // response_iv_ already snapshots the matching IV, so the one-frame
    // predecessor can be destroyed before the bridge sends its ACK.
    this->retired_ = CryptoContext{};
  } else if (this->pending_.valid) {
    ESP_LOGD(TAG, "Accepted delayed frame under active predecessor IV");
  }

  return Action::COMMAND;
}

bool LockSession::is_iv_request_(const std::string &frame) const {
  return frame.size() >= SESSION_IV_REQ_MIN &&
         static_cast<uint8_t>(frame[0]) == PROTOCOL_MAGIC &&
         static_cast<uint8_t>(frame[1]) == 0x00 &&
         static_cast<uint8_t>(frame[2]) == 0x00 &&
         static_cast<uint8_t>(frame[3]) == 0x00 &&
         static_cast<uint8_t>(frame[4]) == 0x0F &&
         static_cast<uint8_t>(frame[5]) == 0x21 &&
         static_cast<uint8_t>(frame[6]) == 0x03;
}

size_t LockSession::encrypt_response(const FrameHeader &header, const uint8_t *plaintext,
                                     size_t length, uint8_t out[MAX_PACKET]) {
  if (length > MAX_PAYLOAD) {
    ESP_LOGE(TAG, "Response payload too large (%zu > %zu)", length, MAX_PAYLOAD);
    return 0;
  }
  out[0] = 0x01;
  out[1] = header.key_id;
  out[2] = header.seq_a;
  out[3] = header.seq_b;
  if (!this->response_iv_valid_ ||
      header.seq_a != this->response_iv_[0] ||
      header.seq_b != this->response_iv_[1]) {
    ESP_LOGE(TAG, "Cannot encrypt response: no matching RX IV context");
    return 0;
  }
  if (!this->xcrypt_(this->response_iv_, plaintext, length, out + HEADER_LEN)) {
    return 0;
  }
  return HEADER_LEN + length;
}

bool LockSession::xcrypt_(const std::array<uint8_t, AES_IV_SIZE> &iv,
                          const uint8_t *input, size_t length, uint8_t *output) {
  return aes_ctr_xcrypt(this->aes_key_, iv.data(), input, output, length);
}

void LockSession::ensure_pending_iv_() {
  // The request carries no transaction identifier. Until a frame proves that
  // the keypad adopted pending_, same-slot requests are retries of the same
  // negotiation and must receive the same IV. Replacing it here strands a
  // command already encrypted with the previously advertised IV (#19).
  if (this->pending_.valid) {
    std::memcpy(this->iv_response_.data() + IV_RESPONSE_HEADER,
                this->pending_.iv.data(), AES_IV_SIZE);
    ESP_LOGV(TAG, "Reusing pending IV: %s",
             format_hex_pretty(this->pending_.iv.data(), AES_IV_SIZE).c_str());
    return;
  }

  // A fresh request starts the next hand-off. The previously retired context
  // is now more than one generation old and must not overlap the new pending
  // IV. Arm a one-shot late-action allowance on the current active context;
  // retries above deliberately neither replace pending_ nor alter this state.
  this->retired_ = CryptoContext{};
  if (this->active_.valid && this->slot_id_ == VISION_KEY_SLOT) {
    this->active_.late_action_allowed = true;
    this->active_.handoff_poll_seen = false;
  } else if (this->active_.valid) {
    this->active_.late_action_allowed = false;
    this->active_.handoff_poll_seen = false;
  }

  this->pending_ = CryptoContext{};
  auto fill_iv = [this]() {
    for (size_t i = 0; i < AES_IV_SIZE; i += 4) {
      const uint32_t value = esp_random();
      std::memcpy(this->pending_.iv.data() + i, &value, 4);
    }
  };
  fill_iv();

  // seq_a/seq_b are the only generation selector carried on the wire. Avoid
  // an ambiguous active/pending pair. Bound the retries so a broken RNG
  // cannot stall the BLE task; the final bit flip still makes the pair unique.
  size_t retries = 0;
  while (this->active_.valid && this->pending_.iv[0] == this->active_.iv[0] &&
         this->pending_.iv[1] == this->active_.iv[1] && retries++ < 4) {
    fill_iv();
  }
  if (this->active_.valid && this->pending_.iv[0] == this->active_.iv[0] &&
      this->pending_.iv[1] == this->active_.iv[1]) {
    this->pending_.iv[1] ^= 0x01;
  }
  this->pending_.valid = true;
  std::memcpy(this->iv_response_.data() + IV_RESPONSE_HEADER,
              this->pending_.iv.data(), AES_IV_SIZE);
  ESP_LOGV(TAG, "Pending IV: %s",
           format_hex_pretty(this->pending_.iv.data(), AES_IV_SIZE).c_str());
}

bool LockSession::is_replayed_action_(const CryptoContext &context,
                                      const DecodedCommand &command) const {
  if (command.type == CommandType::LOCK) {
    return context.lock_seen;
  }
  const int method = unlock_method_index(command.method);
  if (command.type != CommandType::UNLOCK || method < 0) {
    return false;
  }
  const size_t index = command.credential_wire_index;
  return (context.unlock_history[method][index / 8] & (1u << (index % 8))) != 0;
}

void LockSession::record_action_(CryptoContext &context, const DecodedCommand &command) {
  if (command.type == CommandType::LOCK) {
    context.lock_seen = true;
    return;
  }
  const int method = unlock_method_index(command.method);
  if (command.type != CommandType::UNLOCK || method < 0) {
    return;
  }
  const size_t index = command.credential_wire_index;
  context.unlock_history[method][index / 8] |= static_cast<uint8_t>(1u << (index % 8));
}

bool LockSession::seq_matches_(const CryptoContext &context,
                               const FrameHeader &header) const {
  return context.valid && header.seq_a == context.iv[0] &&
         header.seq_b == context.iv[1];
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
