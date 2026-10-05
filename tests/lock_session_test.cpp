#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "components/switchbot_keypad_bridge/aes_ctr.h"
#include "components/switchbot_keypad_bridge/lock_session.h"

namespace {

using esphome::switchbot_keypad_bridge::CommandType;
using esphome::switchbot_keypad_bridge::LockSession;
using esphome::switchbot_keypad_bridge::UnlockMethod;

constexpr psa_key_id_t TEST_KEY = 0x42;
constexpr uint8_t SLOT_VISION = 0xC6;
constexpr uint8_t SLOT_TOUCH = 0x88;
constexpr std::array<uint8_t, 4> STATE_POLL = {0x0F, 0x4F, 0x81, 0x00};
constexpr std::array<uint8_t, 8> LOCK = {0x0F, 0x4E, 0x01, 0x03,
                                         0x00, 0x00, 0x00, 0x00};
constexpr std::array<uint8_t, 8> UNLOCK = {0x0F, 0x4E, 0x01, 0x03,
                                           0x04, 0x80, 0x00, 0x00};
constexpr std::array<uint8_t, 8> FINGERPRINT_UNLOCK = {
    0x0F, 0x4E, 0x01, 0x03, 0x0C, 0x80, 0x00, 0x00};
constexpr std::array<uint8_t, 8> PALM_UNLOCK = {
    0x0F, 0x4E, 0x01, 0x03, 0x20, 0x80, 0x00, 0x00};
constexpr std::array<uint8_t, 8> UNKNOWN_METHOD_UNLOCK = {
    0x0F, 0x4E, 0x01, 0x03, 0x7C, 0x80, 0x00, 0x00};
constexpr std::array<uint8_t, 2> DOORBELL = {0x01, 0x03};
constexpr std::array<uint8_t, 4> UNKNOWN = {0xAA, 0xBB, 0xCC, 0xDD};

std::deque<uint32_t> random_values;

std::array<uint8_t, 16> make_iv(uint8_t first) {
  std::array<uint8_t, 16> iv{};
  for (size_t i = 0; i < iv.size(); ++i) {
    iv[i] = static_cast<uint8_t>(first + i);
  }
  return iv;
}

void queue_iv(const std::array<uint8_t, 16> &iv) {
  for (size_t i = 0; i < iv.size(); i += sizeof(uint32_t)) {
    uint32_t word;
    std::memcpy(&word, iv.data() + i, sizeof(word));
    random_values.push_back(word);
  }
}

std::string iv_request(uint8_t slot = SLOT_VISION) {
  const uint8_t bytes[8] = {0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03, slot};
  return {reinterpret_cast<const char *>(bytes), sizeof(bytes)};
}

std::array<uint8_t, 16> response_iv(const LockSession &session) {
  std::array<uint8_t, 16> iv{};
  std::memcpy(iv.data(), session.iv_response() + 4, iv.size());
  return iv;
}

template<size_t N>
std::string encrypted_frame(const std::array<uint8_t, 16> &iv,
                            const std::array<uint8_t, N> &plaintext,
                            uint8_t slot = SLOT_VISION) {
  std::vector<uint8_t> wire(LockSession::HEADER_LEN + plaintext.size());
  wire[0] = 0x57;
  wire[1] = slot;
  wire[2] = iv[0];
  wire[3] = iv[1];
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), plaintext.data(), wire.data() + LockSession::HEADER_LEN,
      plaintext.size());
  assert(ok);
  return {reinterpret_cast<const char *>(wire.data()), wire.size()};
}

void assert_response_uses_iv(LockSession &session,
                             const std::array<uint8_t, 16> &iv) {
  const uint8_t plaintext[3] = {0x81, 0x08, 0x08};
  uint8_t packet[LockSession::MAX_PACKET]{};
  const size_t size = session.encrypt_response(session.header(), plaintext,
                                                sizeof(plaintext), packet);
  assert(size == LockSession::HEADER_LEN + sizeof(plaintext));

  uint8_t decoded[sizeof(plaintext)]{};
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), packet + LockSession::HEADER_LEN, decoded,
      sizeof(decoded));
  assert(ok);
  assert(std::memcmp(decoded, plaintext, sizeof(plaintext)) == 0);
}

template<size_t N>
void assert_rejected_retired_attempt_closes_handoff(
    const std::array<uint8_t, N> &payload, uint8_t seed) {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto predecessor_iv = make_iv(seed);
  const auto current_iv = make_iv(static_cast<uint8_t>(seed + 0x20));
  queue_iv(predecessor_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(current_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  assert(session.process_frame(encrypted_frame(predecessor_iv, payload)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(
             encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_iv_handoff_and_replay() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x10);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == active_iv);

  const std::string active_poll = encrypted_frame(active_iv, STATE_POLL);
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);

  // A BLE reconnect clears only transient transport state. The logical crypto
  // generation and its replay history stay alive.
  session.reset_transport();
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);

  const auto pending_iv = make_iv(0x30);
  queue_iv(pending_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == pending_iv);

  // Queue the next generation as a sentinel. Same-slot retries must not
  // consume it or replace the uncommitted pending IV, even across reconnects.
  const auto next_iv = make_iv(0x50);
  queue_iv(next_iv);
  session.reset_transport();
  for (size_t i = 0; i < 3; ++i) {
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(response_iv(session) == pending_iv);
  }

  // The reported Vision Pro race: finish an old state poll after advertising
  // the next IV, and encrypt the reply with the old generation.
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);
  assert_response_uses_iv(session, active_iv);

  // A reconnect preserves the negotiated contexts for #19, but deliberately
  // revokes the one-connection Fast Unlock overlap.
  const std::string active_lock = encrypted_frame(active_iv, LOCK);
  assert(session.process_frame(active_lock) == LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(active_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);

  // The first frame under pending_ promotes it. Its replay entry moves with
  // the context, so repeating the same state-changing ciphertext is rejected.
  const std::string pending_lock = encrypted_frame(pending_iv, LOCK);
  assert(session.process_frame(pending_lock) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::LOCK);
  assert(session.process_frame(pending_lock) == LockSession::Action::NONE);

  // The previous generation is gone once pending_ has been proven active.
  assert(session.process_frame(active_poll) == LockSession::Action::NONE);

  // Doorbell remains intentionally outside the side-effect replay filter.
  const std::string doorbell = encrypted_frame(pending_iv, DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);

  // Once pending_ has been proven and promoted, the next request starts a
  // genuinely new generation and consumes the queued RNG sentinel.
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == next_iv);

  // The previous active generation remains available for a delayed poll and
  // one Fast Unlock action while the new IV is still pending.
  const std::string pending_poll = encrypted_frame(pending_iv, STATE_POLL);
  assert(session.process_frame(pending_poll) == LockSession::Action::COMMAND);
  assert_response_uses_iv(session, pending_iv);
  const std::string pending_unlock = encrypted_frame(pending_iv, UNLOCK);
  assert(session.process_frame(pending_unlock) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::UNLOCK);
  assert_response_uses_iv(session, pending_iv);
  assert(session.process_frame(pending_unlock) == LockSession::Action::NONE);

  // Retrying the same IV negotiation is idempotent and cannot re-arm the
  // predecessor capability after its one permitted action was consumed.
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == next_iv);
  assert(session.process_frame(
             encrypted_frame(pending_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);

  // A frame under next_iv commits the new generation and retires pending_iv.
  assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  assert(session.process_frame(pending_poll) == LockSession::Action::NONE);

  // A full crypto reset (unpair/re-key) rejects the formerly active IV.
  session.reset();
  assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
         LockSession::Action::NONE);
}

void test_fast_unlock_after_pending_promotion() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x21);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Fast Unlock ordering #2: the periodic poll commits pending_ before an
  // unlock already encrypted with the predecessor reaches the bridge.
  const auto next_iv = make_iv(0x41);
  queue_iv(next_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  assert_response_uses_iv(session, next_iv);

  const std::string late_unlock =
      encrypted_frame(active_iv, FINGERPRINT_UNLOCK);
  assert(session.process_frame(late_unlock) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::UNLOCK);
  assert(session.command().method == UnlockMethod::FINGERPRINT);
  assert_response_uses_iv(session, active_iv);

  // Consuming the one-shot predecessor removes it permanently.
  assert(session.process_frame(late_unlock) == LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(active_iv, LOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_fast_unlock_before_pending_promotion() {
  {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x2E);
    const auto pending_iv = make_iv(0x4E);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(pending_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);

    // Ordering #1 from #22: the credential action arrives immediately after
    // the new IV advertisement and before any poll commits it.
    assert(session.process_frame(
               encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, predecessor_iv);
    assert(session.process_frame(encrypted_frame(pending_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
  }

  {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x2F);
    const auto pending_iv = make_iv(0x4F);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(pending_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);

    // Plaintext IV retries neither advance nor close the event-bound handoff.
    for (size_t i = 0; i < 3; ++i) {
      assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
      assert(response_iv(session) == pending_iv);
    }
    assert(session.process_frame(encrypted_frame(predecessor_iv, UNLOCK)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, predecessor_iv);
    assert(session.process_frame(encrypted_frame(pending_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
  }
}

void test_predecessor_replay_consumes_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto predecessor_iv = make_iv(0x31);
  const auto pending_iv = make_iv(0x51);
  queue_iv(predecessor_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  const std::string accepted_unlock = encrypted_frame(predecessor_iv, UNLOCK);
  assert(session.process_frame(accepted_unlock) == LockSession::Action::COMMAND);

  queue_iv(pending_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(accepted_unlock) == LockSession::Action::NONE);

  // The rejected replay was still the first predecessor non-poll attempt and
  // consumes the capability; a different old unlock cannot follow it.
  assert(session.process_frame(
             encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(pending_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_rejected_predecessor_attempts_close_handoff() {
  // The first predecessor non-poll frame consumes the one-shot regardless of
  // whether it is admissible. This prevents unlimited probing without time.
  assert_rejected_retired_attempt_closes_handoff(UNKNOWN, 0x27);
  assert_rejected_retired_attempt_closes_handoff(DOORBELL, 0x28);
  assert_rejected_retired_attempt_closes_handoff(UNKNOWN_METHOD_UNLOCK, 0x29);
}

void test_rejected_active_predecessor_attempt_closes_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto predecessor_iv = make_iv(0x2D);
  const auto current_iv = make_iv(0x4D);
  queue_iv(predecessor_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(current_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(predecessor_iv, DOORBELL)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(
             encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_late_lock_is_admitted_once() {
  {
    // Ordering seen on a Keypad Vision with Fast Unlock: the lock button is
    // pressed right after an IV request, before any frame commits pending_.
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x60);
    const auto pending_iv = make_iv(0x61);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(pending_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);

    const std::string late_lock = encrypted_frame(predecessor_iv, LOCK);
    assert(session.process_frame(late_lock) == LockSession::Action::COMMAND);
    assert(session.command().type == CommandType::LOCK);
    assert_response_uses_iv(session, predecessor_iv);

    // One-shot: a second late action under the predecessor is refused.
    assert(session.process_frame(late_lock) == LockSession::Action::NONE);
    assert(session.process_frame(
               encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
           LockSession::Action::NONE);
    assert(session.process_frame(encrypted_frame(pending_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
  }

  {
    // The other ordering: a poll commits the new IV first, then the lock
    // encrypted with the predecessor arrives.
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x62);
    const auto current_iv = make_iv(0x63);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);

    const std::string late_lock = encrypted_frame(predecessor_iv, LOCK);
    assert(session.process_frame(late_lock) == LockSession::Action::COMMAND);
    assert(session.command().type == CommandType::LOCK);
    assert_response_uses_iv(session, predecessor_iv);
    // The predecessor is gone after its one late action.
    assert(session.process_frame(late_lock) == LockSession::Action::NONE);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
  }
}

void test_predecessor_lock_replay_consumes_handoff() {
  for (bool promote_pending : {false, true}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x64);
    const auto current_iv = make_iv(0x65);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);

    const std::string accepted_lock = encrypted_frame(predecessor_iv, LOCK);
    assert(session.process_frame(accepted_lock) == LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    if (promote_pending) {
      assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
             LockSession::Action::COMMAND);
    }

    // Rotating the IV must not make an already executed Lock admissible again,
    // before or after the new generation's first poll. A rejected replay also
    // consumes the shared allowance, so a different old Unlock cannot follow.
    assert(session.process_frame(accepted_lock) == LockSession::Action::NONE);
    assert(session.plaintext_size() == 0);
    assert(session.process_frame(
               encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
           LockSession::Action::NONE);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, current_iv);
    assert(session.process_frame(encrypted_frame(current_iv, LOCK)) ==
           LockSession::Action::COMMAND);
  }
}

void test_transport_reset_revokes_late_lock_handoff() {
  for (bool promote_pending : {false, true}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x66);
    const auto current_iv = make_iv(0x67);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    if (promote_pending) {
      assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
             LockSession::Action::COMMAND);
    }

    // A reconnect revokes both forms of the predecessor allowance, even for
    // a Lock that has never been seen. The negotiated current IV stays usable.
    session.reset_transport();
    assert(session.process_frame(encrypted_frame(predecessor_iv, LOCK)) ==
           LockSession::Action::NONE);
    assert(session.plaintext_size() == 0);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, current_iv);
    assert(session.process_frame(encrypted_frame(current_iv, LOCK)) ==
           LockSession::Action::COMMAND);
  }
}

void test_late_lock_is_rejected_after_handoff_closes() {
  for (bool promote_pending : {false, true}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x68);
    const auto current_iv = make_iv(0x69);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);

    // Two predecessor polls close the pending hand-off. After promotion, one
    // further current-generation poll discards the retained predecessor.
    const auto &poll_iv = promote_pending ? current_iv : predecessor_iv;
    const std::string poll = encrypted_frame(poll_iv, STATE_POLL);
    assert(session.process_frame(poll) == LockSession::Action::COMMAND);
    assert(session.process_frame(poll) == LockSession::Action::COMMAND);
    assert(session.process_frame(encrypted_frame(predecessor_iv, LOCK)) ==
           LockSession::Action::NONE);
    assert(session.plaintext_size() == 0);
    assert(session.process_frame(encrypted_frame(current_iv, LOCK)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, current_iv);
  }
}

void test_poll_budget_closes_state_only_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto predecessor_iv = make_iv(0x2A);
  const auto current_iv = make_iv(0x4A);
  queue_iv(predecessor_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  const std::string predecessor_poll =
      encrypted_frame(predecessor_iv, STATE_POLL);
  assert(session.process_frame(predecessor_poll) == LockSession::Action::COMMAND);

  queue_iv(current_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);

  // One in-flight predecessor poll is tolerated. A second closes the action
  // allowance, while the new generation can still commit normally.
  assert(session.process_frame(predecessor_poll) == LockSession::Action::COMMAND);
  assert(session.process_frame(predecessor_poll) == LockSession::Action::COMMAND);
  assert(session.process_frame(
             encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_next_encrypted_frame_closes_retired_handoff() {
  {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x2B);
    const auto current_iv = make_iv(0x4B);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);

    // A current-generation poll is the next valid encrypted frame, so the
    // predecessor action can no longer follow it.
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    assert(session.process_frame(
               encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
           LockSession::Action::NONE);
  }

  {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto predecessor_iv = make_iv(0x2C);
    const auto current_iv = make_iv(0x4C);
    queue_iv(predecessor_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(current_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(current_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);

    // A delayed predecessor poll may be answered, but it consumes the same
    // next-frame hand-off opportunity.
    assert(session.process_frame(encrypted_frame(predecessor_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    assert_response_uses_iv(session, predecessor_iv);
    assert(session.process_frame(
               encrypted_frame(predecessor_iv, FINGERPRINT_UNLOCK)) ==
           LockSession::Action::NONE);
  }
}

void test_current_generation_action_closes_retired_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto old_iv = make_iv(0x24);
  const auto active_iv = make_iv(0x44);
  queue_iv(old_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(old_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Once a newer side effect has been accepted, an older unlock must never
  // run afterwards and invert that state transition.
  assert(session.process_frame(encrypted_frame(active_iv, LOCK)) ==
         LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::LOCK);
  assert(session.process_frame(encrypted_frame(old_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
}

void test_transport_reset_revokes_fast_unlock_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto iv_a = make_iv(0x25);
  const auto iv_b = make_iv(0x45);
  const auto iv_c = make_iv(0x65);
  queue_iv(iv_a);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv_a, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // active+pending survive reconnect for protocol continuity, but the late
  // action allowance belongs to the old BLE transport and is revoked.
  queue_iv(iv_b);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  session.reset_transport();
  assert(session.process_frame(encrypted_frame(iv_a, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(iv_b, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Exercise the same boundary after a poll created retired_.
  queue_iv(iv_c);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv_c, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  session.reset_transport();
  assert(session.process_frame(encrypted_frame(iv_b, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(iv_c, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_continuous_fast_unlock_rotations_keep_one_predecessor() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto iv_a = make_iv(0x12);
  const auto iv_b = make_iv(0x32);
  const auto iv_c = make_iv(0x52);

  queue_iv(iv_a);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv_a, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(iv_b);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv_b, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(iv_c);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(iv_c, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // After A -> B -> C, only B is the immediate predecessor. This reproduces
  // the seq-mismatch variant of #22 without admitting arbitrarily old IVs.
  assert(session.process_frame(encrypted_frame(iv_a, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  const std::string late_b = encrypted_frame(iv_b, FINGERPRINT_UNLOCK);
  assert(session.process_frame(late_b) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::UNLOCK);
  assert_response_uses_iv(session, iv_b);
  assert(session.process_frame(late_b) == LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(iv_c, STATE_POLL)) ==
         LockSession::Action::COMMAND);
}

void test_slot_change_invalidates_crypto_generations() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto vision_active_iv = make_iv(0x80);
  queue_iv(vision_active_iv);
  assert(session.process_frame(iv_request(SLOT_VISION)) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(vision_active_iv, STATE_POLL, SLOT_VISION)) ==
         LockSession::Action::COMMAND);

  const auto vision_pending_iv = make_iv(0xA0);
  queue_iv(vision_pending_iv);
  assert(session.process_frame(iv_request(SLOT_VISION)) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == vision_pending_iv);

  // A slot change is a hard crypto boundary, not a retry of the Vision
  // transaction. It must discard both old contexts and advertise a fresh IV.
  const auto touch_iv = make_iv(0xC0);
  queue_iv(touch_iv);
  assert(session.process_frame(iv_request(SLOT_TOUCH)) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == touch_iv);

  // Relabelling either old context with the new, unauthenticated key_id must
  // not make it admissible under the Touch slot.
  assert(session.process_frame(encrypted_frame(vision_active_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(vision_pending_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(touch_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::COMMAND);

  // Touch deliberately gets no predecessor allowance. Its previous generation is
  // dropped when the next poll commits, while the new generation stays active.
  const auto touch_next_iv = make_iv(0xD0);
  queue_iv(touch_next_iv);
  assert(session.process_frame(iv_request(SLOT_TOUCH)) == LockSession::Action::SEND_IV);
  assert(session.process_frame(
             encrypted_frame(touch_iv, FINGERPRINT_UNLOCK, SLOT_TOUCH)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(touch_next_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::COMMAND);

  // Switching back is another hard boundary; neither Touch generation can be
  // relabelled for Vision.
  const auto new_vision_iv = make_iv(0xE0);
  queue_iv(new_vision_iv);
  assert(session.process_frame(iv_request(SLOT_VISION)) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == new_vision_iv);
  assert(session.process_frame(encrypted_frame(touch_iv, STATE_POLL, SLOT_VISION)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(touch_next_iv, STATE_POLL, SLOT_VISION)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(new_vision_iv, STATE_POLL, SLOT_VISION)) ==
         LockSession::Action::COMMAND);

  // Create a real Vision retired+active pair, then switch slots once more.
  // Both generations must be discarded at that hard crypto boundary.
  const auto vision_next_iv = make_iv(0x18);
  queue_iv(vision_next_iv);
  assert(session.process_frame(iv_request(SLOT_VISION)) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(vision_next_iv, STATE_POLL, SLOT_VISION)) ==
         LockSession::Action::COMMAND);

  const auto final_touch_iv = make_iv(0x38);
  queue_iv(final_touch_iv);
  assert(session.process_frame(iv_request(SLOT_TOUCH)) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == final_touch_iv);
  assert(session.process_frame(encrypted_frame(new_vision_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(vision_next_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(final_touch_iv, STATE_POLL, SLOT_TOUCH)) ==
         LockSession::Action::COMMAND);
}

void test_full_reset_clears_retired_generation() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto old_iv = make_iv(0xA4);
  const auto active_iv = make_iv(0xC4);
  queue_iv(old_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(old_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  session.reset();
  assert(session.process_frame(encrypted_frame(old_iv, FINGERPRINT_UNLOCK)) ==
         LockSession::Action::NONE);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::NONE);
}

void test_seq_collision_is_resolved() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x70);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Simulate a broken RNG returning the same IV for every bounded retry.
  for (size_t i = 0; i < 5; ++i) {
    queue_iv(active_iv);
  }
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  const auto pending_iv = response_iv(session);
  assert(pending_iv[0] != active_iv[0] || pending_iv[1] != active_iv[1]);
}

void test_iv_request_requires_complete_fixed_header() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  for (const size_t index : {size_t{2}, size_t{3}, size_t{4}}) {
    std::string malformed = iv_request();
    malformed[index] = static_cast<char>(
        static_cast<uint8_t>(malformed[index]) ^ 0x01);
    assert(session.process_frame(malformed) == LockSession::Action::NONE);
  }

  const auto iv = make_iv(0x76);
  queue_iv(iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == iv);
}

void assert_dropped_without_response(LockSession &session, const std::string &frame) {
  assert(session.process_frame(frame) == LockSession::Action::NONE);
  assert(session.plaintext_size() == 0);
  assert(session.command().type == CommandType::UNKNOWN);
  const uint8_t reply[] = {0x81, 0x08, 0x08};
  uint8_t packet[LockSession::MAX_PACKET]{};
  assert(session.encrypt_response(session.header(), reply, sizeof(reply), packet) == 0);
}

void test_action_history_never_evicts() {
  for (const uint8_t slot : {SLOT_VISION, SLOT_TOUCH}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto iv = make_iv(0x36);
    queue_iv(iv);
    assert(session.process_frame(iv_request(slot)) == LockSession::Action::SEND_IV);
    const auto first_lock = encrypted_frame(iv, LOCK, slot);
    assert(session.process_frame(first_lock) == LockSession::Action::COMMAND);

    const UnlockMethod methods[] = {UnlockMethod::PIN, UnlockMethod::NFC,
                                   UnlockMethod::FINGERPRINT, UnlockMethod::FACE,
                                   UnlockMethod::PALM};
    static_assert(sizeof(methods) / sizeof(methods[0]) ==
                  esphome::switchbot_keypad_bridge::UNLOCK_METHOD_COUNT);
    // Exhaust every supported method and all 256 credential-byte values,
    // well beyond the old eight-entry cache.
    for (const auto method : methods) {
      for (size_t wire_index = 0; wire_index <= 0xFF; ++wire_index) {
        auto command = UNLOCK;
        command[4] = static_cast<uint8_t>(method);
        command[6] = static_cast<uint8_t>(wire_index);
        const auto frame = encrypted_frame(iv, command, slot);
        assert(session.process_frame(frame) == LockSession::Action::COMMAND);
        assert(session.command().method == method);
        assert(session.command().credential_wire_index == wire_index);
        assert(session.command().credential_index ==
               static_cast<int16_t>(wire_index >= 0x0A ? wire_index - 0x0A : wire_index));
        assert_dropped_without_response(session, frame);
      }
    }
    assert_dropped_without_response(session, first_lock);
    assert_dropped_without_response(session, encrypted_frame(iv, UNLOCK, slot));
    session.reset_transport();
    assert_dropped_without_response(session, first_lock);
    assert_dropped_without_response(session, encrypted_frame(iv, UNLOCK, slot));

    // History is scoped to the IV; the same legitimate action can be used
    // again after a new generation has been adopted.
    const auto next_iv = make_iv(0x56);
    queue_iv(next_iv);
    assert(session.process_frame(iv_request(slot)) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(next_iv, LOCK, slot)) ==
           LockSession::Action::COMMAND);
    assert(session.process_frame(encrypted_frame(next_iv, UNLOCK, slot)) ==
           LockSession::Action::COMMAND);
  }
}

void test_unlock_padding_and_length_do_not_bypass_history() {
  LockSession session;
  session.set_aes_key(TEST_KEY);
  const auto iv = make_iv(0x3A);
  queue_iv(iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  const auto original = encrypted_frame(iv, UNLOCK);
  assert(session.process_frame(original) == LockSession::Action::COMMAND);
  for (size_t byte = 0; byte <= 0xFF; ++byte) {
    std::string modified = original;
    modified[LockSession::HEADER_LEN + 7] = static_cast<char>(
        static_cast<uint8_t>(modified[LockSession::HEADER_LEN + 7]) ^ byte);
    assert_dropped_without_response(session, modified);
  }
  // Longer frames still decode to the same action, not a new replay identity.
  for (size_t length = original.size() + 1;
       length <= LockSession::MAX_PACKET; ++length) {
    std::string modified = original;
    modified.resize(length, static_cast<char>(0xA5));
    assert_dropped_without_response(session, modified);
  }
  auto aliased_index = UNLOCK;
  aliased_index[6] = 0x0A;
  // The existing display heuristic maps 0x00 and 0x0A alike. Keep the
  // original byte for history so legitimate distinct credentials do not
  // suppress one another; changing credential IDs is an unauthenticated
  // new action, which this protocol cannot protect against.
  assert(session.process_frame(encrypted_frame(iv, aliased_index)) ==
         LockSession::Action::COMMAND);
  assert_dropped_without_response(session, encrypted_frame(iv, aliased_index));
}

void test_modified_predecessor_replay_consumes_handoff() {
  for (const bool promote_pending : {false, true}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto previous_iv = make_iv(0x3B);
    const auto next_iv = make_iv(0x5B);
    queue_iv(previous_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    auto observed = encrypted_frame(previous_iv, UNLOCK);
    assert(session.process_frame(observed) == LockSession::Action::COMMAND);
    queue_iv(next_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    if (promote_pending) {
      assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
             LockSession::Action::COMMAND);
    }
    observed[LockSession::HEADER_LEN + 7] ^= 0x01;
    assert_dropped_without_response(session, observed);
    assert_dropped_without_response(session, encrypted_frame(previous_iv, LOCK));
    assert(session.process_frame(encrypted_frame(next_iv, UNLOCK)) ==
           LockSession::Action::COMMAND);
  }
}

void test_unknown_commands_and_methods_are_dropped() {
  LockSession session;
  session.set_aes_key(TEST_KEY);
  const auto iv = make_iv(0x3C);
  queue_iv(iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  // Unsupported frames cannot promote pending_ or reach the relay.
  assert_dropped_without_response(session, encrypted_frame(iv, UNKNOWN));
  for (size_t method = 0; method <= 0xFF; ++method) {
    if (esphome::switchbot_keypad_bridge::unlock_method_index(
            static_cast<UnlockMethod>(method)) >= 0) {
      continue;
    }
    auto command = UNLOCK;
    command[4] = static_cast<uint8_t>(method);
    assert_dropped_without_response(session, encrypted_frame(iv, command));
  }
  assert(session.process_frame(encrypted_frame(iv, UNLOCK)) ==
         LockSession::Action::COMMAND);
  assert_dropped_without_response(session, encrypted_frame(iv, UNKNOWN));
  assert_dropped_without_response(session, encrypted_frame(iv, UNKNOWN_METHOD_UNLOCK));
}

void test_palm_unlock_uses_one_shot_handoff() {
  for (const bool promote_pending : {false, true}) {
    LockSession session;
    session.set_aes_key(TEST_KEY);
    const auto previous_iv = make_iv(0x3D);
    const auto next_iv = make_iv(0x5D);
    queue_iv(previous_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    assert(session.process_frame(encrypted_frame(previous_iv, STATE_POLL)) ==
           LockSession::Action::COMMAND);
    queue_iv(next_iv);
    assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
    if (promote_pending) {
      assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
             LockSession::Action::COMMAND);
    }
    assert(session.process_frame(encrypted_frame(previous_iv, PALM_UNLOCK)) ==
           LockSession::Action::COMMAND);
    assert(session.command().method == UnlockMethod::PALM);
    assert_response_uses_iv(session, previous_iv);
    assert_dropped_without_response(session, encrypted_frame(previous_iv, PALM_UNLOCK));
    assert_dropped_without_response(session, encrypted_frame(previous_iv, UNLOCK));
  }
}

void test_unsupported_pending_frame_closes_action_handoff() {
  LockSession session;
  session.set_aes_key(TEST_KEY);
  const auto previous_iv = make_iv(0x3E);
  const auto next_iv = make_iv(0x5E);
  queue_iv(previous_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(previous_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  queue_iv(next_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert_dropped_without_response(session, encrypted_frame(next_iv, UNKNOWN));
  assert_dropped_without_response(session, encrypted_frame(next_iv, UNKNOWN_METHOD_UNLOCK));
  // Unsupported next-generation traffic still revokes the predecessor's
  // action capability. It cannot execute an action or commit the next IV,
  // while delayed state-only polls retain the proper response context.
  assert_dropped_without_response(session, encrypted_frame(previous_iv, LOCK));
  assert(session.process_frame(encrypted_frame(previous_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  assert_response_uses_iv(session, previous_iv);
  assert(session.process_frame(encrypted_frame(next_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);
  assert_dropped_without_response(session, encrypted_frame(previous_iv, UNLOCK));
  assert(session.process_frame(encrypted_frame(next_iv, UNLOCK)) ==
         LockSession::Action::COMMAND);
}

}  // namespace

uint32_t esp_random() {
  assert(!random_values.empty());
  const uint32_t value = random_values.front();
  random_values.pop_front();
  return value;
}

namespace esphome {
namespace switchbot_keypad_bridge {

bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    output[i] = input[i] ^ iv[i % 16] ^ static_cast<uint8_t>(key);
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome

int main() {
  test_iv_handoff_and_replay();
  test_fast_unlock_before_pending_promotion();
  test_fast_unlock_after_pending_promotion();
  test_predecessor_replay_consumes_handoff();
  test_rejected_predecessor_attempts_close_handoff();
  test_rejected_active_predecessor_attempt_closes_handoff();
  test_late_lock_is_admitted_once();
  test_predecessor_lock_replay_consumes_handoff();
  test_transport_reset_revokes_late_lock_handoff();
  test_late_lock_is_rejected_after_handoff_closes();
  test_poll_budget_closes_state_only_handoff();
  test_next_encrypted_frame_closes_retired_handoff();
  test_current_generation_action_closes_retired_handoff();
  test_transport_reset_revokes_fast_unlock_handoff();
  test_continuous_fast_unlock_rotations_keep_one_predecessor();
  test_slot_change_invalidates_crypto_generations();
  test_full_reset_clears_retired_generation();
  test_seq_collision_is_resolved();
  test_iv_request_requires_complete_fixed_header();
  test_action_history_never_evicts();
  test_unlock_padding_and_length_do_not_bypass_history();
  test_modified_predecessor_replay_consumes_handoff();
  test_unknown_commands_and_methods_are_dropped();
  test_palm_unlock_uses_one_shot_handoff();
  test_unsupported_pending_frame_closes_action_handoff();
  assert(random_values.empty());
  return 0;
}
