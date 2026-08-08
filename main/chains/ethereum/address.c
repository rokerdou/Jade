#ifndef AMALGAMATED_BUILD
#include "address.h"

#include "../../crypto/keccak256.h"

#include <ctype.h>
#include <string.h>
#include <wally_crypto.h>

static char ethereum_address_hex_char(const uint8_t value)
{
    return value < 10 ? (char)('0' + value) : (char)('a' + value - 10);
}

bool ethereum_address_from_uncompressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, uint8_t* const output, const size_t output_len)
{
    if (!pubkey || pubkey_len != EC_PUBLIC_KEY_UNCOMPRESSED_LEN || pubkey[0] != 0x04 || !output
        || output_len != ETHEREUM_ADDRESS_LEN || wally_ec_public_key_verify(pubkey, pubkey_len) != WALLY_OK) {
        return false;
    }

    uint8_t hash[KECCAK256_LEN];
    if (!keccak256(pubkey + 1, EC_PUBLIC_KEY_UNCOMPRESSED_LEN - 1, hash, sizeof(hash))) {
        return false;
    }

    memcpy(output, hash + KECCAK256_LEN - ETHEREUM_ADDRESS_LEN, output_len);
    wally_bzero(hash, sizeof(hash));
    return true;
}

bool ethereum_address_matches_uncompressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, const uint8_t* const address, const size_t address_len)
{
    if (!address || address_len != ETHEREUM_ADDRESS_LEN) {
        return false;
    }

    uint8_t derived[ETHEREUM_ADDRESS_LEN];
    if (!ethereum_address_from_uncompressed_pubkey(pubkey, pubkey_len, derived, sizeof(derived))) {
        return false;
    }

    const bool matches = memcmp(derived, address, sizeof(derived)) == 0;
    wally_bzero(derived, sizeof(derived));
    return matches;
}

bool ethereum_address_to_checksum_string(
    const uint8_t* const address, const size_t address_len, char* const output, const size_t output_len)
{
    if (!address || address_len != ETHEREUM_ADDRESS_LEN || !output
        || output_len < ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN) {
        return false;
    }

    char lower_hex[ETHEREUM_ADDRESS_LEN * 2 + 1];
    for (size_t i = 0; i < ETHEREUM_ADDRESS_LEN; ++i) {
        lower_hex[2 * i] = ethereum_address_hex_char((uint8_t)(address[i] >> 4));
        lower_hex[(2 * i) + 1] = ethereum_address_hex_char((uint8_t)(address[i] & 0x0f));
    }
    lower_hex[sizeof(lower_hex) - 1] = '\0';

    uint8_t checksum_hash[KECCAK256_LEN];
    if (!keccak256((const uint8_t*)lower_hex, sizeof(lower_hex) - 1, checksum_hash, sizeof(checksum_hash))) {
        wally_bzero(lower_hex, sizeof(lower_hex));
        return false;
    }

    output[0] = '0';
    output[1] = 'x';
    for (size_t i = 0; i < ETHEREUM_ADDRESS_LEN * 2; ++i) {
        const uint8_t hash_nibble
            = (i & 1) ? (uint8_t)(checksum_hash[i / 2] & 0x0f) : (uint8_t)(checksum_hash[i / 2] >> 4);
        output[2 + i] = hash_nibble >= 8 ? (char)toupper((unsigned char)lower_hex[i]) : lower_hex[i];
    }
    output[ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN - 1] = '\0';

    wally_bzero(checksum_hash, sizeof(checksum_hash));
    wally_bzero(lower_hex, sizeof(lower_hex));
    return true;
}
#endif /* AMALGAMATED_BUILD */
