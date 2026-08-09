#ifndef WALLET_CORE_H_
#define WALLET_CORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_crypto.h>

#include "../jade_assert.h"

#define WALLET_CORE_MAX_PATH_LEN 16
#define WALLET_CORE_CHAIN_CODE_LEN 32
#define WALLET_CORE_COMPRESSED_PUBLIC_KEY_LEN EC_PUBLIC_KEY_LEN
#define WALLET_CORE_XPUB_MAX_LEN 128

typedef struct {
    uint32_t parts[WALLET_CORE_MAX_PATH_LEN];
    size_t len;
} wallet_core_path_t;

typedef enum {
    WALLET_CORE_PUBKEY_COMPRESSED = EC_PUBLIC_KEY_LEN,
    WALLET_CORE_PUBKEY_UNCOMPRESSED = EC_PUBLIC_KEY_UNCOMPRESSED_LEN,
} wallet_core_pubkey_format_t;

typedef struct {
    uint8_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[WALLET_CORE_CHAIN_CODE_LEN];
    uint8_t public_key[WALLET_CORE_COMPRESSED_PUBLIC_KEY_LEN];
    char xpub[WALLET_CORE_XPUB_MAX_LEN];
    uint32_t root_fingerprint;
} wallet_core_public_node_t;

bool wallet_core_is_unlocked(void);
bool wallet_core_is_initialized(void);
bool wallet_core_is_ready(void);
bool wallet_core_path_valid(const wallet_core_path_t* path);
bool wallet_core_get_fingerprint(uint8_t* output, size_t output_len);

WARN_UNUSED_RESULT bool wallet_core_get_public_key(
    const wallet_core_path_t* path, wallet_core_pubkey_format_t format, uint8_t* output, size_t output_len);
WARN_UNUSED_RESULT bool wallet_core_get_public_node(const wallet_core_path_t* path, wallet_core_public_node_t* output);
WARN_UNUSED_RESULT bool wallet_core_get_public_node_with_version(
    const wallet_core_path_t* path, uint32_t bip32_public_version, wallet_core_public_node_t* output);

/*
 * Low-level digest signing primitive.
 *
 * This function does not perform user confirmation and must only be called by
 * chain modules after they have parsed the request and completed the required
 * on-device confirmation flow. It never exposes derived private keys to callers.
 */
WARN_UNUSED_RESULT bool wallet_core_sign_digest_ecdsa_recoverable(
    const wallet_core_path_t* path, const uint8_t* digest, size_t digest_len, uint8_t* signature, size_t signature_len);

#endif /* WALLET_CORE_H_ */
