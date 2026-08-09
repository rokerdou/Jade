#ifndef AMALGAMATED_BUILD
#include "address.h"

#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>

static bool hash160_compressed_pubkey(const uint8_t* const pubkey, const size_t pubkey_len, uint8_t hash[HASH160_LEN])
{
    return pubkey && pubkey_len == EC_PUBLIC_KEY_LEN && hash
        && wally_hash160(pubkey, pubkey_len, hash, HASH160_LEN) == WALLY_OK;
}

static bool copy_wally_address(char* const encoded, char* const output, const size_t output_len)
{
    if (!encoded || !output || output_len == 0) {
        return false;
    }

    const size_t encoded_len = strlen(encoded);
    const bool ok = encoded_len + 1 <= output_len;
    if (ok) {
        memcpy(output, encoded, encoded_len + 1);
    }
    return ok;
}

bool bitcoin_p2pkh_testnet_address_from_compressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, char* const output, const size_t output_len)
{
    uint8_t address_bytes[1 + HASH160_LEN];
    memset(address_bytes, 0, sizeof(address_bytes));
    address_bytes[0] = WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    char* encoded = NULL;
    bool ok = hash160_compressed_pubkey(pubkey, pubkey_len, address_bytes + 1)
        && wally_base58_from_bytes(address_bytes, sizeof(address_bytes), BASE58_FLAG_CHECKSUM, &encoded) == WALLY_OK
        && copy_wally_address(encoded, output, output_len);

    if (!ok && output_len) {
        output[0] = '\0';
    }
    if (encoded) {
        wally_free_string(encoded);
    }
    wally_bzero(address_bytes, sizeof(address_bytes));
    return ok;
}

bool bitcoin_p2wpkh_testnet_address_from_compressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, char* const output, const size_t output_len)
{
    uint8_t scriptpubkey[2 + HASH160_LEN];
    memset(scriptpubkey, 0, sizeof(scriptpubkey));
    scriptpubkey[0] = 0x00;
    scriptpubkey[1] = HASH160_LEN;
    char* encoded = NULL;
    bool ok = hash160_compressed_pubkey(pubkey, pubkey_len, scriptpubkey + 2)
        && wally_addr_segwit_from_bytes(scriptpubkey, sizeof(scriptpubkey), "tb", 0, &encoded) == WALLY_OK
        && copy_wally_address(encoded, output, output_len);

    if (!ok && output_len) {
        output[0] = '\0';
    }
    if (encoded) {
        wally_free_string(encoded);
    }
    wally_bzero(scriptpubkey, sizeof(scriptpubkey));
    return ok;
}

bool bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey(
    const uint8_t* const pubkey, const size_t pubkey_len, char* const output, const size_t output_len)
{
    uint8_t redeem_script[2 + HASH160_LEN];
    uint8_t address_bytes[1 + HASH160_LEN];
    memset(redeem_script, 0, sizeof(redeem_script));
    memset(address_bytes, 0, sizeof(address_bytes));
    redeem_script[0] = 0x00;
    redeem_script[1] = HASH160_LEN;
    address_bytes[0] = WALLY_ADDRESS_VERSION_P2SH_TESTNET;
    char* encoded = NULL;
    bool ok = hash160_compressed_pubkey(pubkey, pubkey_len, redeem_script + 2)
        && wally_hash160(redeem_script, sizeof(redeem_script), address_bytes + 1, HASH160_LEN) == WALLY_OK
        && wally_base58_from_bytes(address_bytes, sizeof(address_bytes), BASE58_FLAG_CHECKSUM, &encoded) == WALLY_OK
        && copy_wally_address(encoded, output, output_len);

    if (!ok && output_len) {
        output[0] = '\0';
    }
    if (encoded) {
        wally_free_string(encoded);
    }
    wally_bzero(redeem_script, sizeof(redeem_script));
    wally_bzero(address_bytes, sizeof(address_bytes));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
