#ifndef AMALGAMATED_BUILD
#include "wallet.h"

#include "address.h"
#include "path.h"

#include <wally_crypto.h>

static bool bitcoin_wallet_address_from_path(const wallet_core_path_t* const path, char* const output,
    const size_t output_len,
    bool (*path_is_supported)(const uint32_t* path, size_t path_len),
    bool (*address_from_pubkey)(const uint8_t* pubkey, size_t pubkey_len, char* output, size_t output_len))
{
    if (!path || !path_is_supported || !path_is_supported(path->parts, path->len) || !output || !address_from_pubkey) {
        return false;
    }

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    const bool ok = wallet_core_get_public_key(path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && address_from_pubkey(pubkey, sizeof(pubkey), output, output_len);
    wally_bzero(pubkey, sizeof(pubkey));
    return ok;
}

bool bitcoin_wallet_p2pkh_testnet_address_from_path(
    const wallet_core_path_t* const path, char* const output, const size_t output_len)
{
    return bitcoin_wallet_address_from_path(path, output, output_len,
        bitcoin_path_is_trezor_connect_state_testnet_p2pkh,
        bitcoin_p2pkh_testnet_address_from_compressed_pubkey);
}

bool bitcoin_wallet_p2wpkh_testnet_address_from_path(
    const wallet_core_path_t* const path, char* const output, const size_t output_len)
{
    return bitcoin_wallet_address_from_path(path, output, output_len,
        bitcoin_path_is_testnet_p2wpkh_signing,
        bitcoin_p2wpkh_testnet_address_from_compressed_pubkey);
}

bool bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(
    const wallet_core_path_t* const path, char* const output, const size_t output_len)
{
    return bitcoin_wallet_address_from_path(path, output, output_len,
        bitcoin_path_is_testnet_p2sh_p2wpkh_signing,
        bitcoin_p2sh_p2wpkh_testnet_address_from_compressed_pubkey);
}

static bool bitcoin_path_is_mainnet_p2wpkh_signing(const uint32_t* const path, const size_t path_len)
{
    return bitcoin_path_is_p2wpkh_signing(path, path_len, false);
}

bool bitcoin_wallet_p2wpkh_mainnet_address_from_path(
    const wallet_core_path_t* const path, char* const output, const size_t output_len)
{
    return bitcoin_wallet_address_from_path(path, output, output_len,
        bitcoin_path_is_mainnet_p2wpkh_signing,
        bitcoin_p2wpkh_mainnet_address_from_compressed_pubkey);
}
#endif /* AMALGAMATED_BUILD */
