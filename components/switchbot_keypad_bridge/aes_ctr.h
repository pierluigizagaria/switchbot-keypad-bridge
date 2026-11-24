#pragma once

// AES-128-CTR on top of PSA Crypto — the one cipher the SwitchBot keypad
// protocol uses. CTR is symmetric, so a single primitive covers both
// encryption (responses) and decryption (incoming commands).

#include <psa/crypto.h>

#include <cstddef>
#include <cstdint>

namespace esphome {
namespace switchbot_keypad_bridge {

// Run AES-128-CTR over `input` with an already-imported PSA key. `output`
// must hold `length` bytes (in-place operation is not supported by PSA).
// Logs and returns false on failure.
bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length);

// One-shot variant for a raw 16-byte key, imported and destroyed around the
// call — the pairing path, where the keypad's cloud key only lives for the
// duration of a single job.
bool aes_ctr_xcrypt_raw_key(const uint8_t key[16], const uint8_t iv[16],
                            const uint8_t *input, uint8_t *output, size_t length);

// AES-128-GCM helpers for newer SwitchBot locks. SwitchBot only carries the
// first two bytes of the authentication tag in the command header, but the full
// tag is still computed here so the caller can copy that prefix.
bool aes_gcm_encrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length, uint8_t tag[16]);

// Decrypt WITHOUT authenticating a received short-tag SwitchBot packet.
// Current client compatibility path only: no received tag is accepted by this
// API. A server authorizing keypad commands must separately calculate and
// verify the received two-byte prefix before releasing plaintext or acting.
bool aes_gcm_decrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length);

// Check the two-byte tag prefix used by the reference client framing (empty
// AAD). Callers may consume output only on success. Failure clears output.
// Input and output must not overlap. This provides 16-bit tag checking only.
bool aes_gcm_decrypt_verify_prefix(const uint8_t key[16], const uint8_t nonce[12],
                                   const uint8_t *input, uint8_t *output,
                                   size_t length, const uint8_t (&prefix)[2]);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
