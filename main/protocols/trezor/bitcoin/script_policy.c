#ifndef AMALGAMATED_BUILD
#include "script_policy.h"

#include "../../../chains/bitcoin/path.h"
#include "../../../wallet_core/wallet_core.h"

#include <string.h>
#include <wally_crypto.h>

#define TREZOR_BITCOIN_P2PKH_SCRIPT_LEN 25U
#define TREZOR_BITCOIN_P2WPKH_SCRIPT_LEN 22U
#define TREZOR_BITCOIN_P2SH_SCRIPT_LEN 23U

static bool trezor_bitcoin_script_policy_path_from_input(
    const trezor_bitcoin_tx_input_t* const input, wallet_core_path_t* const path)
{
    if (!input || !path || input->address_n_len == 0 || input->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    wally_bzero(path, sizeof(*path));
    path->len = input->address_n_len;
    memcpy(path->parts, input->address_n, input->address_n_len * sizeof(input->address_n[0]));
    return true;
}

static bool trezor_bitcoin_script_policy_pubkey_hash_from_input(
    const trezor_bitcoin_tx_input_t* const input, uint8_t pubkey_hash[HASH160_LEN])
{
    wallet_core_path_t path;
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    wally_bzero(&path, sizeof(path));
    wally_bzero(pubkey, sizeof(pubkey));

    const bool ok = trezor_bitcoin_script_policy_path_from_input(input, &path)
        && wallet_core_get_public_key(&path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && wally_hash160(pubkey, sizeof(pubkey), pubkey_hash, HASH160_LEN) == WALLY_OK;

    wally_bzero(&path, sizeof(path));
    wally_bzero(pubkey, sizeof(pubkey));
    if (!ok) {
        wally_bzero(pubkey_hash, HASH160_LEN);
    }
    return ok;
}

static bool trezor_bitcoin_script_policy_build_p2pkh(
    const trezor_bitcoin_tx_input_t* const input, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < TREZOR_BITCOIN_P2PKH_SCRIPT_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_script_policy_pubkey_hash_from_input(input, pubkey_hash);
    if (ok) {
        script[0] = 0x76;
        script[1] = 0xa9;
        script[2] = HASH160_LEN;
        memcpy(script + 3, pubkey_hash, HASH160_LEN);
        script[3 + HASH160_LEN] = 0x88;
        script[4 + HASH160_LEN] = 0xac;
        *written = TREZOR_BITCOIN_P2PKH_SCRIPT_LEN;
    }
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    return ok;
}

static bool trezor_bitcoin_script_policy_build_p2wpkh(
    const trezor_bitcoin_tx_input_t* const input, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < TREZOR_BITCOIN_P2WPKH_SCRIPT_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_script_policy_pubkey_hash_from_input(input, pubkey_hash);
    if (ok) {
        script[0] = 0x00;
        script[1] = HASH160_LEN;
        memcpy(script + 2, pubkey_hash, HASH160_LEN);
        *written = TREZOR_BITCOIN_P2WPKH_SCRIPT_LEN;
    }
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    return ok;
}

static bool trezor_bitcoin_script_policy_build_p2sh_p2wpkh(
    const trezor_bitcoin_tx_input_t* const input, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < TREZOR_BITCOIN_P2SH_SCRIPT_LEN || !written) {
        return false;
    }

    uint8_t redeem_script[TREZOR_BITCOIN_P2WPKH_SCRIPT_LEN];
    uint8_t redeem_hash[HASH160_LEN];
    size_t redeem_script_len = 0;
    wally_bzero(redeem_script, sizeof(redeem_script));
    wally_bzero(redeem_hash, sizeof(redeem_hash));

    const bool ok = trezor_bitcoin_script_policy_build_p2wpkh(
                        input, redeem_script, sizeof(redeem_script), &redeem_script_len)
        && redeem_script_len == sizeof(redeem_script)
        && wally_hash160(redeem_script, sizeof(redeem_script), redeem_hash, sizeof(redeem_hash)) == WALLY_OK;
    if (ok) {
        script[0] = 0xa9;
        script[1] = HASH160_LEN;
        memcpy(script + 2, redeem_hash, HASH160_LEN);
        script[2 + HASH160_LEN] = 0x87;
        *written = TREZOR_BITCOIN_P2SH_SCRIPT_LEN;
    }

    wally_bzero(redeem_script, sizeof(redeem_script));
    wally_bzero(redeem_hash, sizeof(redeem_hash));
    return ok;
}

static bool trezor_bitcoin_script_policy_multisig_variant_matches_script_type(
    const trezor_bitcoin_tx_input_t* const input)
{
    if (!input || !input->has_multisig || input->multisig.threshold == 0
        || input->multisig.num_pubkeys == 0 || input->multisig.threshold > input->multisig.num_pubkeys
        || input->multisig.num_pubkeys > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS) {
        return false;
    }
    if (input->script_type == BITCOIN_MULTISIG_SPENDMULTISIG) {
        return input->multisig.variant == MULTI_P2SH;
    }
    if (input->script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        return input->multisig.variant == MULTI_P2WSH;
    }
    if (input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        return input->multisig.variant == MULTI_P2WSH_P2SH;
    }
    return false;
}

static bool trezor_bitcoin_script_policy_multisig_prevout_matches_input(
    const trezor_bitcoin_tx_input_t* const input, const uint8_t* const script_pubkey, const size_t script_pubkey_len)
{
    return input && script_pubkey && script_pubkey_len > 0
        && trezor_bitcoin_script_policy_multisig_variant_matches_script_type(input)
        && input->multisig.script_pubkey_len == script_pubkey_len
        && input->multisig.script_pubkey_len <= sizeof(input->multisig.script_pubkey)
        && memcmp(input->multisig.script_pubkey, script_pubkey, script_pubkey_len) == 0;
}

bool trezor_bitcoin_script_policy_prevout_matches_input(const trezor_bitcoin_tx_input_t* const input,
    const trezor_bitcoin_coin_t coin, const uint8_t* const script_pubkey, const size_t script_pubkey_len)
{
    if (!input || !script_pubkey || script_pubkey_len == 0
        || script_pubkey_len > TREZOR_BITCOIN_STANDARD_PREVOUT_SCRIPT_MAX_LEN) {
        return false;
    }
    if (input->has_multisig) {
        (void)coin;
        return trezor_bitcoin_script_policy_multisig_prevout_matches_input(input, script_pubkey, script_pubkey_len);
    }

    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    const bool path_ok = input->script_type == BITCOIN_P2PKH_SPENDADDRESS
            ? bitcoin_path_is_p2pkh_signing(input->address_n, input->address_n_len, testnet)
        : input->script_type == BITCOIN_P2WPKH_SPENDWITNESS
            ? bitcoin_path_is_p2wpkh_signing(input->address_n, input->address_n_len, testnet)
        : input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
            ? bitcoin_path_is_p2sh_p2wpkh_signing(input->address_n, input->address_n_len, testnet)
            : false;
    if (!path_ok) {
        return false;
    }

    uint8_t expected[TREZOR_BITCOIN_STANDARD_PREVOUT_SCRIPT_MAX_LEN];
    size_t expected_len = 0;
    wally_bzero(expected, sizeof(expected));
    const bool built = input->script_type == BITCOIN_P2PKH_SPENDADDRESS
            ? trezor_bitcoin_script_policy_build_p2pkh(input, expected, sizeof(expected), &expected_len)
        : input->script_type == BITCOIN_P2WPKH_SPENDWITNESS
            ? trezor_bitcoin_script_policy_build_p2wpkh(input, expected, sizeof(expected), &expected_len)
        : input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
            ? trezor_bitcoin_script_policy_build_p2sh_p2wpkh(input, expected, sizeof(expected), &expected_len)
            : false;

    const bool ok = built && expected_len == script_pubkey_len
        && memcmp(expected, script_pubkey, script_pubkey_len) == 0;
    wally_bzero(expected, sizeof(expected));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
