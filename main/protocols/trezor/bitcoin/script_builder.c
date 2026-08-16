#ifndef AMALGAMATED_BUILD
#include "script_builder.h"

#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_script.h>

static uint32_t trezor_bitcoin_script_builder_wally_network(const trezor_bitcoin_coin_t coin)
{
    return trezor_bitcoin_coin_is_testnet(coin) ? WALLY_NETWORK_BITCOIN_TESTNET : WALLY_NETWORK_BITCOIN_MAINNET;
}

static bool trezor_bitcoin_script_builder_path_from_output(
    const trezor_bitcoin_tx_output_t* const output, wallet_core_path_t* const path)
{
    if (!output || !path || output->address_n_len == 0 || output->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    wally_bzero(path, sizeof(*path));
    path->len = output->address_n_len;
    memcpy(path->parts, output->address_n, output->address_n_len * sizeof(output->address_n[0]));
    return true;
}

static bool trezor_bitcoin_script_builder_pubkey_hash_from_path(
    const wallet_core_path_t* const path, uint8_t hash[HASH160_LEN])
{
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    wally_bzero(pubkey, sizeof(pubkey));
    const bool ok = path && wallet_core_get_public_key(path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && wally_hash160(pubkey, sizeof(pubkey), hash, HASH160_LEN) == WALLY_OK;
    wally_bzero(pubkey, sizeof(pubkey));
    if (!ok) {
        wally_bzero(hash, HASH160_LEN);
    }
    return ok;
}

bool trezor_bitcoin_script_builder_p2pkh_script_code_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < WALLY_SCRIPTPUBKEY_P2PKH_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_script_builder_pubkey_hash_from_path(path, pubkey_hash);
    if (ok) {
        script[0] = 0x76;
        script[1] = 0xa9;
        script[2] = HASH160_LEN;
        memcpy(script + 3, pubkey_hash, HASH160_LEN);
        script[3 + HASH160_LEN] = 0x88;
        script[4 + HASH160_LEN] = 0xac;
        *written = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
    }
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    return ok;
}

static bool trezor_bitcoin_script_builder_p2wpkh_script_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < WALLY_SCRIPTPUBKEY_P2WPKH_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_script_builder_pubkey_hash_from_path(path, pubkey_hash);
    if (ok) {
        script[0] = 0x00;
        script[1] = HASH160_LEN;
        memcpy(script + 2, pubkey_hash, HASH160_LEN);
        *written = WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    }
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    return ok;
}

static bool trezor_bitcoin_script_builder_p2sh_p2wpkh_script_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < WALLY_SCRIPTPUBKEY_P2SH_LEN || !written) {
        return false;
    }

    uint8_t redeem_script[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    uint8_t redeem_hash[HASH160_LEN];
    size_t redeem_script_len = 0;
    wally_bzero(redeem_script, sizeof(redeem_script));
    wally_bzero(redeem_hash, sizeof(redeem_hash));
    const bool ok = trezor_bitcoin_script_builder_p2wpkh_script_from_path(path, redeem_script, sizeof(redeem_script),
                        &redeem_script_len)
        && redeem_script_len == sizeof(redeem_script)
        && wally_hash160(redeem_script, sizeof(redeem_script), redeem_hash, sizeof(redeem_hash)) == WALLY_OK;
    if (ok) {
        script[0] = 0xa9;
        script[1] = HASH160_LEN;
        memcpy(script + 2, redeem_hash, HASH160_LEN);
        script[2 + HASH160_LEN] = 0x87;
        *written = WALLY_SCRIPTPUBKEY_P2SH_LEN;
    }
    wally_bzero(redeem_script, sizeof(redeem_script));
    wally_bzero(redeem_hash, sizeof(redeem_hash));
    return ok;
}

bool trezor_bitcoin_script_builder_p2sh_p2wpkh_scriptsig_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < 1U + WALLY_SCRIPTPUBKEY_P2WPKH_LEN || !written) {
        return false;
    }
    script[0] = WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    const bool ok = trezor_bitcoin_script_builder_p2wpkh_script_from_path(
        path, script + 1, script_len - 1U, written);
    if (ok) {
        *written += 1U;
    }
    return ok;
}

bool trezor_bitcoin_script_builder_p2pkh_scriptsig_from_signature(const uint8_t* const signature,
    const size_t signature_len, const uint8_t* const pubkey, const size_t pubkey_len, uint8_t* const script,
    const size_t script_len, size_t* const written)
{
    if (!signature || signature_len < 2U || signature_len > 75U || !pubkey || pubkey_len != EC_PUBLIC_KEY_LEN
        || !script || !written || script_len < (2U + signature_len + pubkey_len)) {
        return false;
    }

    script[0] = (uint8_t)signature_len;
    memcpy(script + 1U, signature, signature_len);
    script[1U + signature_len] = (uint8_t)pubkey_len;
    memcpy(script + 2U + signature_len, pubkey, pubkey_len);
    *written = 2U + signature_len + pubkey_len;
    return true;
}

bool trezor_bitcoin_script_builder_output_script(const trezor_bitcoin_tx_output_t* const output,
    const trezor_bitcoin_coin_t coin, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!output || !script || !written) {
        return false;
    }
    *written = 0;

    if (output->has_address) {
        if (wally_addr_segwit_to_bytes(output->address, trezor_bitcoin_coin_segwit_hrp(coin), 0, script,
                script_len, written)
                == WALLY_OK
            && *written > 0) {
            return true;
        }
        *written = 0;
        return wally_address_to_scriptpubkey(output->address, trezor_bitcoin_script_builder_wally_network(coin),
                   script, script_len, written)
            == WALLY_OK
            && (*written == WALLY_SCRIPTPUBKEY_P2PKH_LEN || *written == WALLY_SCRIPTPUBKEY_P2SH_LEN);
    }

    wallet_core_path_t path;
    wally_bzero(&path, sizeof(path));
    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    if (output->address_n_len < 3) {
        wally_bzero(&path, sizeof(path));
        return false;
    }
    const uint32_t account = output->address_n[2];
    const bool ok = trezor_bitcoin_script_builder_path_from_output(output, &path)
        && (bitcoin_path_is_p2pkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_script_builder_p2pkh_script_code_from_path(&path, script, script_len, written)
            : bitcoin_path_is_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_script_builder_p2wpkh_script_from_path(&path, script, script_len, written)
            : bitcoin_path_is_p2sh_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_script_builder_p2sh_p2wpkh_script_from_path(&path, script, script_len, written)
                : false);
    wally_bzero(&path, sizeof(path));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
