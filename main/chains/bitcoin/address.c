#ifndef AMALGAMATED_BUILD
#include "address.h"

#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>

bool bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, char* const output, const size_t output_len)
{
    if (!pubkey || pubkey_len != EC_PUBLIC_KEY_LEN || !output || output_len == 0) {
        return false;
    }

    uint8_t address_bytes[1 + HASH160_LEN];
    address_bytes[0] = WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    char* encoded = NULL;
    bool ok = wally_hash160(pubkey, pubkey_len, address_bytes + 1, HASH160_LEN) == WALLY_OK
        && wally_base58_from_bytes(address_bytes, sizeof(address_bytes), BASE58_FLAG_CHECKSUM, &encoded) == WALLY_OK
        && encoded;
    if (ok) {
        const size_t encoded_len = strlen(encoded);
        ok = encoded_len + 1 <= output_len;
        if (ok) {
            memcpy(output, encoded, encoded_len + 1);
        }
    }

    if (!ok && output_len) {
        output[0] = '\0';
    }
    if (encoded) {
        wally_free_string(encoded);
    }
    wally_bzero(address_bytes, sizeof(address_bytes));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
