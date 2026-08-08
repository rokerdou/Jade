#ifndef AMALGAMATED_BUILD
#include "address.h"

#include "../ethereum/address.h"

#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>

bool tron_address_from_uncompressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, uint8_t* const output, const size_t output_len)
{
    if (!output || output_len != TRON_ADDRESS_LEN) {
        return false;
    }

    uint8_t eth_address[ETHEREUM_ADDRESS_LEN];
    if (!ethereum_address_from_uncompressed_pubkey(pubkey, pubkey_len, eth_address, sizeof(eth_address))) {
        return false;
    }

    output[0] = TRON_ADDRESS_PREFIX;
    memcpy(output + 1, eth_address, sizeof(eth_address));
    wally_bzero(eth_address, sizeof(eth_address));
    return true;
}

bool tron_owner_address_matches_uncompressed_pubkey(const uint8_t* const pubkey, const size_t pubkey_len,
    const uint8_t* const owner_address, const size_t owner_address_len)
{
    if (!owner_address || owner_address_len != TRON_ADDRESS_LEN || owner_address[0] != TRON_ADDRESS_PREFIX) {
        return false;
    }

    uint8_t derived[TRON_ADDRESS_LEN];
    if (!tron_address_from_uncompressed_pubkey(pubkey, pubkey_len, derived, sizeof(derived))) {
        return false;
    }

    const bool matches = memcmp(derived, owner_address, sizeof(derived)) == 0;
    wally_bzero(derived, sizeof(derived));
    return matches;
}

bool tron_address_to_base58(
    const uint8_t* const address, const size_t address_len, char* const output, const size_t output_len)
{
    if (!address || address_len != TRON_ADDRESS_LEN || address[0] != TRON_ADDRESS_PREFIX || !output || !output_len) {
        return false;
    }

    char* encoded = NULL;
    if (wally_base58_from_bytes(address, address_len, BASE58_FLAG_CHECKSUM, &encoded) != WALLY_OK || !encoded) {
        return false;
    }

    const size_t encoded_len = strlen(encoded);
    if (encoded_len + 1 > output_len) {
        wally_free_string(encoded);
        return false;
    }

    memcpy(output, encoded, encoded_len + 1);
    wally_free_string(encoded);
    return true;
}
#endif /* AMALGAMATED_BUILD */
