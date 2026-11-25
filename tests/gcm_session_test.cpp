#include <cassert>
#include <cstring>
#include <string>
#include "components/switchbot_keypad_bridge/gcm_session.h"
#include "components/switchbot_keypad_bridge/aes_ctr.h"

static uint8_t seed = 0;
extern "C" void esp_fill_random(void *data, size_t size) {
  std::memset(data, 0, size);
  static_cast<uint8_t *>(data)[11] = ++seed;
}
namespace esphome {
namespace switchbot_keypad_bridge {
// Deterministic crypto doubles isolate session policy. Test real AES separately.
bool aes_gcm_decrypt_verify_prefix(const uint8_t *, const uint8_t *nonce,
    const uint8_t *in, uint8_t *out, size_t n, const uint8_t (&tag)[2]) {
  if (tag[0] != nonce[11] || tag[1] != 0xA5) return false;
  std::memcpy(out, in, n);
  return true;
}
bool aes_gcm_encrypt_raw_key(const uint8_t *, const uint8_t *nonce,
    const uint8_t *in, uint8_t *out, size_t n, uint8_t *tag) {
  std::memcpy(out, in, n); tag[0] = nonce[11]; tag[1] = 0xA5; return true;
}
}
}
using namespace esphome::switchbot_keypad_bridge;
const std::array<uint8_t, 16> key{};
std::string handshake() { const char b[] = {0x57,0,0,0,0x0F,0x21,3,char(0x88)}; return {b,8}; }
std::string packet(uint8_t nonce, std::initializer_list<uint8_t> body) {
  std::string out;
  for (auto c : {uint8_t(0x57),uint8_t(0x88),nonce,uint8_t(0xA5)}) out += char(c);
  for (auto c : body) out += char(c);
  return out;
}
uint8_t open(GcmSession &s, uint32_t now = 0) {
  s.begin(1, now);
  assert(s.process(handshake(), 1, now, key, true));
  assert(s.response().size() == 20);
  auto value = s.response();
  assert(s.process(handshake(), 1, now, key, true));
  assert(s.response() == value);
  return uint8_t(value[15]);
}
int main() {
  for (auto method : {uint8_t(0x0C),uint8_t(0x04),uint8_t(0x08)}) {
    GcmSession s; auto n = open(s);
    auto action = packet(n, {0x0F,0x4E,1,3,method,0x80,0x0B,0});
    assert(s.process(action,1,10,key,true));
    assert(s.response().size() == 9);
    auto response = s.response();
    assert(s.process(action,1,20,key,true) && s.response() == response);
    for (uint8_t i=1; i<=3; ++i) {
      auto poll = packet(n+i,{0x0F,0x4F,0x81,1});
      assert(s.process(poll,1,100+i,key,true));
      assert(s.response().size()==18 && uint8_t(s.response()[4])==0x94);
    }
    auto poll_repeat = packet(n+3,{0x0F,0x4F,0x81,1});
    response = s.response();
    assert(s.process(poll_repeat,1,200,key,true) && s.response() == response);
    DecodedCommand decoded;
    assert(s.finish(1,500,decoded));
    assert(decoded.method==static_cast<UnlockMethod>(method) && decoded.credential_index==1);
    assert(!s.finish(1,501,decoded));
    auto next = open(s,600);
    assert(next != n);
    assert(!s.process(action,1,601,key,true));
    assert(!s.finish(1,700,decoded));
  }
  GcmSession lock; auto n=open(lock);
  assert(lock.process(packet(n,{0x0F,0x4E,1,3,0,0,0,0}),1,1,key,true));
  assert(uint8_t(lock.response()[4])==0x86);
  assert(lock.process(packet(n+1,{0x0F,0x4F,0x81,1}),1,2,key,true));
  assert(uint8_t(lock.response()[4])==0x86);
  DecodedCommand action;
  assert(lock.finish(1,3,action) && action.type==CommandType::LOCK);

  GcmSession invalid; n=open(invalid);
  auto altered=packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}); altered[3]^=1;
  assert(!invalid.process(altered,1,1,key,true));
  assert(!invalid.finish(1,2,action));

  GcmSession stale; n=open(stale);
  auto request=packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0});
  assert(stale.process(request,1,1,key,true));
  assert(stale.process(packet(n+1,{0x0F,0x4F,0x81,1}),1,2,key,true));
  assert(!stale.process(request,1,3,key,true));
  assert(!stale.finish(1,4,action));

  GcmSession timeout; n=open(timeout);
  assert(timeout.process(packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}),1,1,key,true));
  assert(timeout.process(packet(n+1,{0x0F,0x4F,0x81,1}),1,2,key,true));
  assert(!timeout.finish(1,10000,action));

  GcmSession incomplete; n=open(incomplete);
  assert(incomplete.process(packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}),1,1,key,true));
  assert(!incomplete.finish(1,2,action));

  GcmSession wrong_connection; n=open(wrong_connection);
  assert(!wrong_connection.process(packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}),2,1,key,true));
  assert(!wrong_connection.finish(2,2,action));
  assert(wrong_connection.process(packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}),1,3,key,true));
  GcmSession rate;
  for (uint32_t i = 0; i < 3; ++i) {
    auto counter = open(rate, i * 1000);
    auto bad = packet(counter,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0});
    bad[3] ^= 1;
    assert(!rate.process(bad,1,i * 1000 + 1,key,true));
    assert(!rate.finish(1,i * 1000 + 2,action));
  }
  rate.begin(1,4000);
  assert(!rate.process(handshake(),1,4001,key,true));
  assert(!rate.finish(1,4002,action));
  open(rate,61000);

  GcmSession too_many;
  n = open(too_many);
  assert(too_many.process(packet(n,{0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}),1,1,key,true));
  for (uint8_t i=1; i<=16; ++i)
    assert(too_many.process(packet(n+i,{0x0F,0x4F,0x81,1}),1,100+i,key,true));
  assert(!too_many.process(packet(n+17,{0x0F,0x4F,0x81,1}),1,200,key,true));
  assert(!too_many.finish(1,201,action));

  // Both project family slots negotiate; pin the slot for this session.
  GcmSession vision;
  vision.begin(1,0);
  auto vision_open = handshake();
  vision_open[7] = char(0xC6);
  assert(vision.process(vision_open,1,0,key,true));
  n = uint8_t(vision.response()[15]);
  auto vision_request = packet(n,{0x0F,0x4E,1,3,0x04,0x80,0x0B,0});
  vision_request[1] = char(0xC6);
  assert(vision.process(vision_request,1,1,key,true));
  auto wrong_slot_poll = packet(n+1,{0x0F,0x4F,0x81,1});
  assert(!vision.process(wrong_slot_poll,1,2,key,true));
  assert(!vision.finish(1,3,action));

}
