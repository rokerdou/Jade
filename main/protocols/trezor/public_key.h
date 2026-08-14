#ifndef TREZOR_PUBLIC_KEY_H_
#define TREZOR_PUBLIC_KEY_H_

#include "../../wallet_core/wallet_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_PUBLIC_KEY_COIN_NAME_MAX_LEN 16

typedef enum {
    TREZOR_PUBLIC_KEY_REQUEST_GENERIC = 0,
    TREZOR_PUBLIC_KEY_REQUEST_ETHEREUM,
} trezor_public_key_request_kind_t;

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool show_display;
    bool has_show_display;
    bool has_coin_name;
    char coin_name[TREZOR_PUBLIC_KEY_COIN_NAME_MAX_LEN];
    bool has_script_type;
    uint32_t script_type;
    bool has_ignore_xpub_magic;
    bool ignore_xpub_magic;
    trezor_public_key_request_kind_t kind;
} trezor_public_key_request_t;

typedef struct {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[WALLET_CORE_CHAIN_CODE_LEN];
    uint8_t public_key[WALLET_CORE_COMPRESSED_PUBLIC_KEY_LEN];
    char xpub[WALLET_CORE_XPUB_MAX_LEN];
    uint32_t root_fingerprint;
    bool has_root_fingerprint;
} trezor_public_key_response_t;

bool trezor_public_key_decode_generic(
    const uint8_t* payload, size_t payload_len, trezor_public_key_request_t* output);
bool trezor_public_key_decode_ethereum(
    const uint8_t* payload, size_t payload_len, trezor_public_key_request_t* output);
bool trezor_public_key_is_root_fingerprint_probe(const trezor_public_key_request_t* request);
bool trezor_public_key_encode_generic(
    const trezor_public_key_response_t* response, uint8_t* output, size_t output_len, size_t* written);
bool trezor_public_key_encode_ethereum(
    const trezor_public_key_response_t* response, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_PUBLIC_KEY_H_ */
