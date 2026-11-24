#include "aes_ctr.h"

#include <aes/esp_aes_gcm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>

extern "C" {
#include <mbedtls/constant_time.h>
}

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {
const char *const TAG = "switchbot_keypad_bridge.crypto";
}  // namespace

bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length) {
  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  size_t out_len = 0;
  size_t finish_len = 0;

  psa_status_t status = psa_cipher_encrypt_setup(&op, key, PSA_ALG_CTR);
  if (status == PSA_SUCCESS) {
    status = psa_cipher_set_iv(&op, iv, 16);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_update(&op, input, length, output, length, &out_len);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_finish(&op, output + out_len, length - out_len, &finish_len);
  }

  if (status != PSA_SUCCESS) {
    psa_cipher_abort(&op);
    ESP_LOGE(TAG, "AES-CTR operation failed (%d)", static_cast<int>(status));
    return false;
  }
  return true;
}

bool aes_ctr_xcrypt_raw_key(const uint8_t key[16], const uint8_t iv[16],
                            const uint8_t *input, uint8_t *output, size_t length) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
  psa_reset_key_attributes(&attrs);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }

  const bool ok = aes_ctr_xcrypt(key_id, iv, input, output, length);
  psa_destroy_key(key_id);
  return ok;
}

bool aes_gcm_encrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length, uint8_t tag[16]) {
  esp_gcm_context ctx;
  esp_aes_gcm_init(&ctx);
  int rc = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
  if (rc == 0) {
    rc = esp_aes_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, length,
                                   iv, 12, nullptr, 0,
                                   input, output, 16, tag);
  }
  esp_aes_gcm_free(&ctx);
  if (rc != 0) {
    ESP_LOGE(TAG, "AES-GCM encrypt failed (%d)", rc);
    return false;
  }
  return true;
}

namespace {
int gcm_decrypt_and_compute_tag(const uint8_t key[16], const uint8_t iv[12],
                                const uint8_t *input, uint8_t *output,
                                size_t length, uint8_t (&tag)[16]) {
  esp_gcm_context ctx;
  esp_aes_gcm_init(&ctx);
  int rc = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
  if (rc == 0) {
    rc = esp_aes_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, length,
                                   iv, 12, nullptr, 0,
                                   input, output, sizeof(tag), tag);
  }
  esp_aes_gcm_free(&ctx);
  return rc;
}
}  // namespace

bool aes_gcm_decrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length) {
  uint8_t ignored_tag[16];
  const int rc = gcm_decrypt_and_compute_tag(key, iv, input, output, length, ignored_tag);
  if (rc != 0) {
    ESP_LOGE(TAG, "AES-GCM decrypt failed (%d)", rc);
    return false;
  }
  return true;
}

bool aes_gcm_decrypt_verify_prefix(const uint8_t key[16], const uint8_t nonce[12],
                                   const uint8_t *input, uint8_t *output,
                                   size_t length, const uint8_t (&prefix)[2]) {
  uint8_t computed_tag[16];
  const int rc = gcm_decrypt_and_compute_tag(key, nonce, input, output, length, computed_tag);
  const bool valid = rc == 0 && mbedtls_ct_memcmp(prefix, computed_tag, sizeof(prefix)) == 0;
  mbedtls_platform_zeroize(computed_tag, sizeof(computed_tag));
  if (!valid && length != 0) {
    mbedtls_platform_zeroize(output, length);
  }
  return valid;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
