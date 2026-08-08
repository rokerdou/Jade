#ifndef AMALGAMATED_BUILD
#include "local_pin.h"

#include "../sensitive.h"

#include <esp_timer.h>
#include <string.h>
#include <wally_crypto.h>

extern uint8_t macid[6];

#ifndef CONFIG_LOCAL_PIN_KDF_COST
#define CONFIG_LOCAL_PIN_KDF_COST 120000
#endif

#define LOCAL_PIN_SALT_LEN SHA256_LEN

static bool local_pin_derive_aeskey(
    const uint8_t* const pin, const size_t pin_len, uint8_t* const aeskey, const size_t aeskey_len)
{
    if (!pin || pin_len == 0 || !aeskey || aeskey_len != AES_KEY_LEN_256) {
        return false;
    }

    static const uint8_t domain[] = "jade-tdisplay-s3-local-pin-v1";
    uint8_t salt_material[sizeof(domain) - 1 + sizeof(macid)];
    uint8_t salt[LOCAL_PIN_SALT_LEN];
    uint8_t derived[PBKDF2_HMAC_SHA512_LEN];
    SENSITIVE_PUSH(salt_material, sizeof(salt_material));
    SENSITIVE_PUSH(salt, sizeof(salt));
    SENSITIVE_PUSH(derived, sizeof(derived));

    memcpy(salt_material, domain, sizeof(domain) - 1);
    memcpy(salt_material + sizeof(domain) - 1, macid, sizeof(macid));

    const int64_t start_us = esp_timer_get_time();
    const bool ok = wally_sha256(salt_material, sizeof(salt_material), salt, sizeof(salt)) == WALLY_OK
        && wally_pbkdf2_hmac_sha512(
               pin, pin_len, salt, sizeof(salt), 0, CONFIG_LOCAL_PIN_KDF_COST, derived, sizeof(derived))
            == WALLY_OK;
    const int64_t elapsed_ms = (esp_timer_get_time() - start_us) / 1000;
    JADE_LOGI("Local PIN KDF cost=%d elapsed=%lld ms", CONFIG_LOCAL_PIN_KDF_COST, elapsed_ms);
    if (ok) {
        memcpy(aeskey, derived, aeskey_len);
    }

    SENSITIVE_POP(derived);
    SENSITIVE_POP(salt);
    SENSITIVE_POP(salt_material);
    return ok;
}

bool local_pin_get_aeskey(
    const uint8_t* const pin, const size_t pin_len, uint8_t* const aeskey, const size_t aeskey_len)
{
    return local_pin_derive_aeskey(pin, pin_len, aeskey, aeskey_len);
}

bool local_pin_set_aeskey(
    const uint8_t* const pin, const size_t pin_len, uint8_t* const aeskey, const size_t aeskey_len)
{
    return local_pin_derive_aeskey(pin, pin_len, aeskey, aeskey_len);
}
#endif /* AMALGAMATED_BUILD */
