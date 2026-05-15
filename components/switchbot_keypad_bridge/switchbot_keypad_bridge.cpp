#include "switchbot_keypad_bridge.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include <esp_random.h>
#include <psa/crypto.h>

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge";

// BLE service / characteristic UUIDs as exposed by a real SwitchBot Lock.
constexpr const char *SERVICE_UUID = "cba20d00-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *RX_CHAR_UUID = "cba20002-224d-11e6-9fb8-0002a5d5c51b";
constexpr const char *TX_CHAR_UUID = "cba20003-224d-11e6-9fb8-0002a5d5c51b";

// Manufacturer-specific advertising blob published by the genuine lock.
constexpr uint8_t ADVERTISING_MFG_DATA[] = {0x27, 0x09, 0x00, 0x10,
                                            0xA5, 0xB8, 0x00, 0x00, 0x00};

// Plain-text command frames as decoded from the keypad.
constexpr uint8_t FRAME_LOCK[8]       = {0x0F, 0x4E, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t FRAME_ACTION[4]     = {0x0F, 0x4E, 0x01, 0x03};
constexpr uint8_t FRAME_STATE_POLL[4] = {0x0F, 0x4F, 0x81, 0x02};

// Encrypted response payloads sent back to the keypad on lock/unlock.
constexpr uint8_t RESPONSE_LOCK[5]   = {0x90, 0x0A, 0x7F, 0x7F, 0x00};
constexpr uint8_t RESPONSE_UNLOCK[5] = {0x98, 0x08, 0x7F, 0x7F, 0x00};

// Trailing 13 bytes appended to the lock-state byte when answering a state poll.
constexpr uint8_t STATE_PAYLOAD_TAIL[13] = {0x08, 0x08, 0x41, 0x00, 0x00, 0x00, 0x00,
                                            0x80, 0xF2, 0xFB, 0x00, 0x00, 0x00};

// Encrypted protocol framing.
constexpr uint8_t  PROTOCOL_MAGIC      = 0x57;
constexpr uint8_t  ENCRYPTED_KEY_ID    = 0x88;
constexpr size_t   ENCRYPTED_HEADER    = 4;     // [0x57, key_id, seq_a, seq_b]
constexpr size_t   MAX_PAYLOAD_LEN     = 32;
constexpr size_t   MIN_PAYLOAD_LEN     = 4;

// Session IV negotiation: first frame received after connect.
constexpr size_t   SESSION_IV_REQ_MIN  = 8;
constexpr uint8_t  SESSION_IV_REQ_BYTE5 = 0x21;
constexpr uint8_t  SESSION_IV_REQ_BYTE6 = 0x03;

// Unlock frame layout: [hdr(4) | method | marker(0x80) | index | ...]
constexpr size_t   UNLOCK_METHOD_OFFSET = 4;
constexpr size_t   UNLOCK_MARKER_OFFSET = 5;
constexpr size_t   UNLOCK_INDEX_OFFSET  = 6;
constexpr uint8_t  UNLOCK_MARKER        = 0x80;
constexpr uint8_t  UNLOCK_INDEX_BASE    = 0x0A;

constexpr size_t   AES_KEY_SIZE   = 16;
constexpr size_t   AES_IV_SIZE    = 16;
constexpr size_t   IV_RESPONSE_HEADER = 4;  // session_iv_response_ prefix before the IV bytes

bool parse_hex(const std::string &hex, uint8_t *out, size_t len) {
  if (hex.size() < len * 2)
    return false;
  for (size_t i = 0; i < len; ++i) {
    if (std::sscanf(hex.c_str() + (i * 2), "%2hhx", &out[i]) != 1)
      return false;
  }
  return true;
}

std::string format_hex_pretty(const uint8_t *data, size_t length) {
  std::string out;
  out.reserve(length * 3);
  for (size_t i = 0; i < length; ++i) {
    char tmp[4];
    std::snprintf(tmp, sizeof(tmp), "%02X%s", data[i], (i + 1 < length) ? " " : "");
    out += tmp;
  }
  return out;
}

}  // namespace

const char *unlock_method_name(UnlockMethod method) {
  switch (method) {
    case UnlockMethod::FINGERPRINT:
      return "fingerprint";
    case UnlockMethod::PIN:
      return "pin";
    default:
      return "unknown";
  }
}

// ---------------------------------------------------------------------------
// NimBLE callback bridges
// ---------------------------------------------------------------------------

class SwitchbotKeypadBridge::ServerCallbacks : public NimBLEServerCallbacks {
 public:
  explicit ServerCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override {
    ESP_LOGI(TAG, "Keypad connected: %s", info.getAddress().toString().c_str());
  }

  void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override {
    ESP_LOGI(TAG, "Keypad disconnected (reason=0x%02X), restarting advertising", reason);
    NimBLEDevice::startAdvertising();
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::RxCharCallbacks : public NimBLECharacteristicCallbacks {
 public:
  explicit RxCharCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onWrite(NimBLECharacteristic *characteristic, NimBLEConnInfo &info) override {
    const std::string value = characteristic->getValue();
    if (value.empty())
      return;
    this->parent_->on_rx_frame_(value);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

// ---------------------------------------------------------------------------
// Component lifecycle
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::setup() {
  if (!this->prepare_keys_() || !this->prepare_ble_()) {
    this->mark_failed();
    return;
  }
  const std::string ble_address = NimBLEDevice::getAddress().toString();
  if (this->ble_mac_text_sensor_ != nullptr) {
    this->ble_mac_text_sensor_->publish_state(ble_address);
  }
  ESP_LOGI(TAG, "Ready. Advertising on %s", ble_address.c_str());
}

void SwitchbotKeypadBridge::dump_config() {
  ESP_LOGCONFIG(TAG, "SwitchBot Keypad Bridge:");
  ESP_LOGCONFIG(TAG, "  BLE address: %s", NimBLEDevice::getAddress().toString().c_str());
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Initialization failed - see previous errors");
  }
}

bool SwitchbotKeypadBridge::prepare_keys_() {
  const psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "PSA Crypto init failed (%d)", static_cast<int>(status));
    return false;
  }
  if (!parse_hex(this->shared_key_hex_, this->aes_key_.data(), this->aes_key_.size())) {
    ESP_LOGE(TAG, "Invalid shared_key: expected 32 hexadecimal characters");
    return false;
  }
  return true;
}

bool SwitchbotKeypadBridge::prepare_ble_() {
  NimBLEDevice::init("WoLock");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  this->server_ = NimBLEDevice::createServer();
  this->server_->setCallbacks(new ServerCallbacks(this));

  NimBLEService *service = this->server_->createService(SERVICE_UUID);
  this->tx_characteristic_ = service->createCharacteristic(TX_CHAR_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      RX_CHAR_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCharCallbacks(this));

  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(service->getUUID());
  advertising->setManufacturerData(
      std::string(reinterpret_cast<const char *>(ADVERTISING_MFG_DATA), sizeof(ADVERTISING_MFG_DATA)));
  advertising->start();
  return true;
}

// ---------------------------------------------------------------------------
// RX path
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::on_rx_frame_(const std::string &frame) {
  ESP_LOGV(TAG, "RX %zu bytes: %s", frame.size(),
           format_hex_pretty(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()).c_str());

  if (this->is_session_iv_request_(frame)) {
    ESP_LOGD(TAG, "Session IV request received");
    this->send_session_iv_();
    return;
  }

  if (frame.size() <= ENCRYPTED_HEADER ||
      static_cast<uint8_t>(frame[0]) != PROTOCOL_MAGIC) {
    ESP_LOGD(TAG, "Ignoring non-protocol frame (size=%zu)", frame.size());
    return;
  }

  const FrameHeader header{static_cast<uint8_t>(frame[1]), static_cast<uint8_t>(frame[2]),
                           static_cast<uint8_t>(frame[3])};

  if (header.key_id != ENCRYPTED_KEY_ID) {
    ESP_LOGD(TAG, "Ignoring frame with unexpected key_id=0x%02X", header.key_id);
    return;
  }

  const size_t ct_len = frame.size() - ENCRYPTED_HEADER;
  if (ct_len < MIN_PAYLOAD_LEN || ct_len > MAX_PAYLOAD_LEN) {
    ESP_LOGW(TAG, "Dropping frame with invalid payload length: %zu", ct_len);
    return;
  }

  std::vector<uint8_t> plaintext(ct_len);
  if (!this->aes_ctr_xcrypt_(reinterpret_cast<const uint8_t *>(frame.data() + ENCRYPTED_HEADER),
                             ct_len, plaintext.data())) {
    return;  // error already logged
  }

  DecodedCommand command;
  if (!this->decode_command_(plaintext.data(), ct_len, command)) {
    ESP_LOGD(TAG, "Unknown command payload: %s", format_hex_pretty(plaintext.data(), ct_len).c_str());
    this->send_ack_(header);
    return;
  }
  this->handle_command_(header, command);
}

bool SwitchbotKeypadBridge::is_session_iv_request_(const std::string &frame) const {
  return frame.size() >= SESSION_IV_REQ_MIN &&
         static_cast<uint8_t>(frame[0]) == PROTOCOL_MAGIC &&
         static_cast<uint8_t>(frame[1]) == 0x00 &&
         static_cast<uint8_t>(frame[5]) == SESSION_IV_REQ_BYTE5 &&
         static_cast<uint8_t>(frame[6]) == SESSION_IV_REQ_BYTE6;
}

void SwitchbotKeypadBridge::send_session_iv_() {
  this->rotate_session_iv_();
  this->notify_(this->session_iv_response_.data(), this->session_iv_response_.size());
}

bool SwitchbotKeypadBridge::decode_command_(const uint8_t *plaintext, size_t length,
                                            DecodedCommand &out) const {
  if (length == sizeof(FRAME_LOCK) && std::memcmp(plaintext, FRAME_LOCK, sizeof(FRAME_LOCK)) == 0) {
    out.type = CommandType::LOCK;
    return true;
  }
  if (length == sizeof(FRAME_STATE_POLL) &&
      std::memcmp(plaintext, FRAME_STATE_POLL, sizeof(FRAME_STATE_POLL)) == 0) {
    out.type = CommandType::STATE_POLL;
    return true;
  }
  if (length >= 8 && std::memcmp(plaintext, FRAME_ACTION, sizeof(FRAME_ACTION)) == 0 &&
      plaintext[UNLOCK_MARKER_OFFSET] == UNLOCK_MARKER) {
    const uint8_t method_byte = plaintext[UNLOCK_METHOD_OFFSET];
    if (method_byte != static_cast<uint8_t>(UnlockMethod::PIN) &&
        method_byte != static_cast<uint8_t>(UnlockMethod::FINGERPRINT)) {
      return false;
    }
    out.type = CommandType::UNLOCK;
    out.method = static_cast<UnlockMethod>(method_byte);
    const uint8_t idx_byte = plaintext[UNLOCK_INDEX_OFFSET];
    out.credential_index = (idx_byte >= UNLOCK_INDEX_BASE)
                               ? static_cast<int16_t>(idx_byte - UNLOCK_INDEX_BASE)
                               : -1;
    return true;
  }
  return false;
}

void SwitchbotKeypadBridge::handle_command_(const FrameHeader &header, const DecodedCommand &command) {
  switch (command.type) {
    case CommandType::LOCK:
      ESP_LOGI(TAG, "Lock command received");
      this->lock_state_ = LockState::LOCKED;
      this->publish_lock_();
      this->send_encrypted_response_(header, RESPONSE_LOCK, sizeof(RESPONSE_LOCK));
      return;

    case CommandType::UNLOCK:
      ESP_LOGI(TAG, "Unlock command received (method=%s, index=%d)",
               unlock_method_name(command.method), command.credential_index);
      this->lock_state_ = LockState::UNLOCKED;
      this->publish_unlock_(command.method, command.credential_index);
      this->send_encrypted_response_(header, RESPONSE_UNLOCK, sizeof(RESPONSE_UNLOCK));
      return;

    case CommandType::STATE_POLL:
      ESP_LOGD(TAG, "State poll received");
      this->handle_state_poll_(header);
      return;

    case CommandType::UNKNOWN:
    default:
      this->send_ack_(header);
      return;
  }
}

void SwitchbotKeypadBridge::handle_state_poll_(const FrameHeader &header) {
  uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
  state_payload[0] = static_cast<uint8_t>(this->lock_state_);
  std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
  this->send_encrypted_response_(header, state_payload, sizeof(state_payload));
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::send_ack_(const FrameHeader &header) {
  const uint8_t ack[ENCRYPTED_HEADER] = {0x01, header.key_id, header.seq_a, header.seq_b};
  this->notify_(ack, sizeof(ack));
}

void SwitchbotKeypadBridge::send_encrypted_response_(const FrameHeader &header,
                                                    const uint8_t *plaintext, size_t length) {
  std::vector<uint8_t> packet(ENCRYPTED_HEADER + length);
  packet[0] = 0x01;
  packet[1] = header.key_id;
  packet[2] = header.seq_a;
  packet[3] = header.seq_b;
  if (!this->aes_ctr_xcrypt_(plaintext, length, packet.data() + ENCRYPTED_HEADER)) {
    return;
  }
  this->notify_(packet.data(), packet.size());
}

void SwitchbotKeypadBridge::notify_(const uint8_t *data, size_t length) {
  this->tx_characteristic_->setValue(data, length);
  this->tx_characteristic_->notify();
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

bool SwitchbotKeypadBridge::aes_ctr_xcrypt_(const uint8_t *input, size_t length, uint8_t *output) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attrs, this->aes_key_.data(), this->aes_key_.size(), &key_id);
  psa_reset_key_attributes(&attrs);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }

  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  size_t out_len = 0;
  size_t finish_len = 0;

  status = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
  if (status == PSA_SUCCESS) {
    status = psa_cipher_set_iv(&op, this->session_iv_response_.data() + IV_RESPONSE_HEADER, AES_IV_SIZE);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_update(&op, input, length, output, length, &out_len);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_finish(&op, output + out_len, length - out_len, &finish_len);
  }

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES-CTR operation failed (%d)", static_cast<int>(status));
    psa_cipher_abort(&op);
  }
  psa_destroy_key(key_id);
  return status == PSA_SUCCESS;
}

void SwitchbotKeypadBridge::rotate_session_iv_() {
  for (size_t i = 0; i < AES_IV_SIZE; i += 4) {
    const uint32_t value = esp_random();
    std::memcpy(this->session_iv_response_.data() + IV_RESPONSE_HEADER + i, &value, 4);
  }
  ESP_LOGV(TAG, "Session IV rotated: %s",
           format_hex_pretty(this->session_iv_response_.data() + IV_RESPONSE_HEADER, AES_IV_SIZE).c_str());
}

// ---------------------------------------------------------------------------
// Eventing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::publish_lock_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("lock");
  }
  this->on_lock_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_unlock_(UnlockMethod method, int index) {
  const char *method_str = unlock_method_name(method);
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("unlock");
  }
  this->on_unlock_callbacks_.call(std::string(method_str), index);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
