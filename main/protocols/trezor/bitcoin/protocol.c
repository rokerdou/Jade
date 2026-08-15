#ifndef AMALGAMATED_BUILD
#include "protocol.h"

#include "policy.h"

#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_address.h>
#include <wally_map.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <wally_crypto.h>

#define TREZOR_BITCOIN_SIGHASH_ALL 1U

static uint32_t trezor_bitcoin_coin_wally_network(const trezor_bitcoin_coin_t coin)
{
    return trezor_bitcoin_coin_is_testnet(coin) ? WALLY_NETWORK_BITCOIN_TESTNET : WALLY_NETWORK_BITCOIN_MAINNET;
}

static bool trezor_bitcoin_output_script(const trezor_bitcoin_tx_output_t* output, trezor_bitcoin_coin_t coin,
    uint8_t* script, size_t script_len, size_t* written);

static bool trezor_bitcoin_protocol_txid_to_wally_hash(
    const uint8_t* const txid, const size_t txid_len, uint8_t hash[SHA256_LEN])
{
    if (!txid || txid_len != SHA256_LEN || !hash) {
        return false;
    }
    for (size_t i = 0; i < SHA256_LEN; ++i) {
        hash[i] = txid[SHA256_LEN - 1U - i];
    }
    return true;
}

static bool trezor_bitcoin_add_u64(uint64_t* const total, const uint64_t value)
{
    if (!total || value > UINT64_MAX - *total) {
        return false;
    }
    *total += value;
    return true;
}

bool trezor_bitcoin_signing_to_confirm_request(
    const trezor_bitcoin_signing_state_t* const state, bitcoin_confirm_request_t* const request)
{
    if (!state || !request || !trezor_bitcoin_policy_is_basic(state)
        || state->inputs[0].address_n_len > CHAIN_CONFIRM_MAX_PATH_LEN) {
        return false;
    }

    wally_bzero(request, sizeof(*request));
    request->path_len = state->inputs[0].address_n_len;
    memcpy(request->path, state->inputs[0].address_n, request->path_len * sizeof(request->path[0]));

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!trezor_bitcoin_policy_signing_coin(state, &coin)) {
        wally_bzero(request, sizeof(*request));
        return false;
    }

    size_t external_outputs = 0;
    for (size_t i = 0; i < state->outputs_len; ++i) {
        const trezor_bitcoin_tx_output_t* const output = &state->outputs[i];
        uint8_t validated_script[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
        size_t validated_script_len = 0;
        wally_bzero(validated_script, sizeof(validated_script));
        const bool valid_output = trezor_bitcoin_output_script(
            output, coin, validated_script, sizeof(validated_script), &validated_script_len);
        wally_bzero(validated_script, sizeof(validated_script));
        if (!valid_output) {
            wally_bzero(request, sizeof(*request));
            return false;
        }
        if (output->has_address) {
            ++external_outputs;
            if (external_outputs == 1) {
                memcpy(request->to, output->address, strlen(output->address) + 1);
            }
            if (!trezor_bitcoin_add_u64(&request->amount, output->amount)) {
                wally_bzero(request, sizeof(*request));
                return false;
            }
        } else if (!trezor_bitcoin_add_u64(&request->change, output->amount)) {
            wally_bzero(request, sizeof(*request));
            return false;
        }
    }
    if (external_outputs != 1 || request->amount == 0 || request->to[0] == '\0') {
        wally_bzero(request, sizeof(*request));
        return false;
    }
    request->fee = state->fee;
    request->fee_rate_sats_per_vbyte = state->fee_rate_sats_per_vbyte;
    return true;
}

static bool trezor_bitcoin_path_from_input(const trezor_bitcoin_tx_input_t* const input, wallet_core_path_t* const path)
{
    if (!input || !path || input->address_n_len == 0 || input->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    wally_bzero(path, sizeof(*path));
    path->len = input->address_n_len;
    memcpy(path->parts, input->address_n, input->address_n_len * sizeof(input->address_n[0]));
    return true;
}

static bool trezor_bitcoin_path_from_output(
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

static bool trezor_bitcoin_pubkey_hash_from_path(const wallet_core_path_t* const path, uint8_t hash[HASH160_LEN])
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

static bool trezor_bitcoin_p2pkh_script_code_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < WALLY_SCRIPTPUBKEY_P2PKH_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_pubkey_hash_from_path(path, pubkey_hash);
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

static bool trezor_bitcoin_p2wpkh_script_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < WALLY_SCRIPTPUBKEY_P2WPKH_LEN || !written) {
        return false;
    }

    uint8_t pubkey_hash[HASH160_LEN];
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    const bool ok = trezor_bitcoin_pubkey_hash_from_path(path, pubkey_hash);
    if (ok) {
        script[0] = 0x00;
        script[1] = HASH160_LEN;
        memcpy(script + 2, pubkey_hash, HASH160_LEN);
        *written = WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    }
    wally_bzero(pubkey_hash, sizeof(pubkey_hash));
    return ok;
}

static bool trezor_bitcoin_p2sh_p2wpkh_script_from_path(
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
    const bool ok = trezor_bitcoin_p2wpkh_script_from_path(path, redeem_script, sizeof(redeem_script),
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

static bool trezor_bitcoin_p2sh_p2wpkh_scriptsig_from_path(
    const wallet_core_path_t* const path, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!script || script_len < 1U + WALLY_SCRIPTPUBKEY_P2WPKH_LEN || !written) {
        return false;
    }
    script[0] = WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    const bool ok = trezor_bitcoin_p2wpkh_script_from_path(
        path, script + 1, script_len - 1U, written);
    if (ok) {
        *written += 1U;
    }
    return ok;
}

static bool trezor_bitcoin_p2pkh_scriptsig_from_signature(
    const uint8_t* const signature, const size_t signature_len, const uint8_t* const pubkey,
    const size_t pubkey_len, uint8_t* const script, const size_t script_len, size_t* const written)
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

static bool trezor_bitcoin_output_script(const trezor_bitcoin_tx_output_t* const output,
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
        return wally_address_to_scriptpubkey(
                   output->address, trezor_bitcoin_coin_wally_network(coin), script, script_len, written)
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
    const bool ok = trezor_bitcoin_path_from_output(output, &path)
        && (bitcoin_path_is_p2pkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_p2pkh_script_code_from_path(&path, script, script_len, written)
            : bitcoin_path_is_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_p2wpkh_script_from_path(&path, script, script_len, written)
            : bitcoin_path_is_p2sh_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                ? trezor_bitcoin_p2sh_p2wpkh_script_from_path(&path, script, script_len, written)
                : false);
    wally_bzero(&path, sizeof(path));
    return ok;
}

static bool trezor_bitcoin_add_unsigned_inputs(
    struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state)
{
    if (!tx || !state) {
        return false;
    }
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        uint8_t wally_txhash[SHA256_LEN];
        wally_bzero(wally_txhash, sizeof(wally_txhash));
        const bool ok = trezor_bitcoin_protocol_txid_to_wally_hash(
            input->prev_hash, sizeof(input->prev_hash), wally_txhash);
        if (!ok
            || wally_tx_add_raw_input(tx, wally_txhash, sizeof(wally_txhash), input->prev_index, input->sequence,
                NULL, 0, NULL, 0)
                != WALLY_OK) {
            wally_bzero(wally_txhash, sizeof(wally_txhash));
            return false;
        }
        wally_bzero(wally_txhash, sizeof(wally_txhash));
    }
    return true;
}

static bool trezor_bitcoin_add_outputs(
    struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state, const trezor_bitcoin_coin_t coin)
{
    if (!tx || !state) {
        return false;
    }
    for (size_t i = 0; i < state->outputs_len; ++i) {
        uint8_t output_script[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
        size_t output_script_len = 0;
        wally_bzero(output_script, sizeof(output_script));
        const bool ok = trezor_bitcoin_output_script(
                            &state->outputs[i], coin, output_script, sizeof(output_script), &output_script_len)
            && wally_tx_add_raw_output(tx, state->outputs[i].amount, output_script, output_script_len, 0) == WALLY_OK;
        wally_bzero(output_script, sizeof(output_script));
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool trezor_bitcoin_signing_build_hash(const trezor_bitcoin_signing_state_t* const state,
    const size_t input_index, wallet_core_path_t* const path, uint8_t* const digest, const size_t digest_len)
{
    if (!trezor_bitcoin_policy_is_basic(state) || input_index >= state->inputs_len || !path || !digest
        || digest_len != SHA256_LEN) {
        return false;
    }

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    const trezor_bitcoin_tx_input_t* const input = &state->inputs[input_index];
    bool ok = false;
    struct wally_tx* tx = NULL;
    struct wally_map values;
    memset(&values, 0, sizeof(values));

    uint8_t script_code[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    size_t script_code_len = 0;
    wally_bzero(script_code, sizeof(script_code));
    wally_bzero(digest, digest_len);

    wallet_core_path_t local_path;
    if (!trezor_bitcoin_policy_signing_coin(state, &coin) || !trezor_bitcoin_path_from_input(input, &local_path)) {
        goto cleanup;
    }

    ok = (input->script_type == BITCOIN_P2PKH_SPENDADDRESS || input->script_type == BITCOIN_P2WPKH_SPENDWITNESS
             || input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)
        && trezor_bitcoin_p2pkh_script_code_from_path(&local_path, script_code, sizeof(script_code), &script_code_len)
        && script_code_len == sizeof(script_code);
    if (!ok) {
        goto cleanup;
    }

    ok = wally_tx_init_alloc(
             state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx && trezor_bitcoin_add_unsigned_inputs(tx, state) && trezor_bitcoin_add_outputs(tx, state, coin)
        && wally_map_init(state->inputs_len, NULL, &values) == WALLY_OK;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        ok = wally_map_add_integer(&values, (uint32_t)i, (const uint8_t*)&state->inputs[i].amount,
                 sizeof(state->inputs[i].amount))
            == WALLY_OK;
    }
    const uint32_t signature_type = input->script_type == BITCOIN_P2PKH_SPENDADDRESS ? WALLY_SIGTYPE_PRE_SW
                                                                                     : WALLY_SIGTYPE_SW_V0;
    ok = ok
        && wally_tx_get_input_signature_hash(tx, input_index, NULL, NULL, &values, script_code, script_code_len, 0,
               WALLY_NO_CODESEPARATOR, NULL, 0, NULL, 0, TREZOR_BITCOIN_SIGHASH_ALL, signature_type, NULL,
               digest, digest_len)
            == WALLY_OK;
    if (ok) {
        *path = local_path;
    }

cleanup:
    if (tx) {
        wally_tx_free(tx);
    }
    wally_map_clear(&values);
    wally_bzero(&local_path, sizeof(local_path));
    wally_bzero(script_code, sizeof(script_code));
    if (!ok) {
        wally_bzero(digest, digest_len);
    }
    return ok;
}

bool trezor_bitcoin_signing_build_p2wpkh_hash(const trezor_bitcoin_signing_state_t* const state,
    const size_t input_index, wallet_core_path_t* const path, uint8_t* const digest, const size_t digest_len)
{
    return trezor_bitcoin_policy_is_p2wpkh_basic(state)
        && trezor_bitcoin_signing_build_hash(state, input_index, path, digest, digest_len);
}

bool trezor_bitcoin_signing_build_signed_tx(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_signature_t* const signatures, const size_t signatures_len, uint8_t* const serialized_tx,
    const size_t serialized_tx_len, size_t* const serialized_tx_written)
{
    if (!trezor_bitcoin_policy_is_basic(state) || !signatures || signatures_len != state->inputs_len
        || !serialized_tx || !serialized_tx_written) {
        return false;
    }

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    bool ok = false;
    struct wally_tx* tx = NULL;
    const bool legacy_p2pkh = state->inputs[0].script_type == BITCOIN_P2PKH_SPENDADDRESS;
    struct wally_tx_witness_stack* witnesses[TREZOR_BITCOIN_TX_INPUTS_MAX];
    for (size_t i = 0; i < TREZOR_BITCOIN_TX_INPUTS_MAX; ++i) {
        witnesses[i] = NULL;
    }

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    wally_bzero(pubkey, sizeof(pubkey));
    *serialized_tx_written = 0;

    ok = trezor_bitcoin_policy_signing_coin(state, &coin)
        && wally_tx_init_alloc(
               state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        wallet_core_path_t path;
        uint8_t wally_txhash[SHA256_LEN];
        uint8_t script_sig[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
        size_t script_sig_len = 0;
        wally_bzero(&path, sizeof(path));
        wally_bzero(wally_txhash, sizeof(wally_txhash));
        wally_bzero(script_sig, sizeof(script_sig));
        ok = signatures[i].len >= 2 && signatures[i].len <= TREZOR_BITCOIN_SIGNATURE_MAX_LEN
            && trezor_bitcoin_path_from_input(&state->inputs[i], &path)
            && wallet_core_get_public_key(&path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
            && trezor_bitcoin_protocol_txid_to_wally_hash(
                state->inputs[i].prev_hash, sizeof(state->inputs[i].prev_hash), wally_txhash);
        if (ok && legacy_p2pkh) {
            ok = state->inputs[i].script_type == BITCOIN_P2PKH_SPENDADDRESS
                && trezor_bitcoin_p2pkh_scriptsig_from_signature(signatures[i].bytes, signatures[i].len, pubkey,
                    sizeof(pubkey), script_sig, sizeof(script_sig), &script_sig_len);
        } else if (ok) {
            ok = wally_tx_witness_stack_init_alloc(2, &witnesses[i]) == WALLY_OK && witnesses[i]
                && wally_tx_witness_stack_add(witnesses[i], signatures[i].bytes, signatures[i].len) == WALLY_OK
                && wally_tx_witness_stack_add(witnesses[i], pubkey, sizeof(pubkey)) == WALLY_OK;
            if (ok && state->inputs[i].script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
                ok = trezor_bitcoin_p2sh_p2wpkh_scriptsig_from_path(
                    &path, script_sig, sizeof(script_sig), &script_sig_len);
            }
        }
        ok = ok
            && wally_tx_add_raw_input(tx, wally_txhash, sizeof(wally_txhash), state->inputs[i].prev_index,
                   state->inputs[i].sequence,
                   script_sig_len ? script_sig : NULL, script_sig_len, witnesses[i], 0)
                == WALLY_OK;
        wally_bzero(&path, sizeof(path));
        wally_bzero(wally_txhash, sizeof(wally_txhash));
        wally_bzero(script_sig, sizeof(script_sig));
        wally_bzero(pubkey, sizeof(pubkey));
    }
    ok = ok && trezor_bitcoin_add_outputs(tx, state, coin)
        && wally_tx_to_bytes(tx, legacy_p2pkh ? 0 : WALLY_TX_FLAG_USE_WITNESS, serialized_tx, serialized_tx_len,
               serialized_tx_written)
            == WALLY_OK;

    if (tx) {
        wally_tx_free(tx);
    }
    for (size_t i = 0; i < TREZOR_BITCOIN_TX_INPUTS_MAX; ++i) {
        if (witnesses[i]) {
            wally_tx_witness_stack_free(witnesses[i]);
        }
    }
    wally_bzero(pubkey, sizeof(pubkey));
    if (!ok) {
        wally_bzero(serialized_tx, serialized_tx_len);
        *serialized_tx_written = 0;
    }
    return ok;
}

bool trezor_bitcoin_signing_build_p2wpkh_signed_tx(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_signature_t* const signatures, const size_t signatures_len, uint8_t* const serialized_tx,
    const size_t serialized_tx_len, size_t* const serialized_tx_written)
{
    return trezor_bitcoin_policy_is_p2wpkh_basic(state)
        && trezor_bitcoin_signing_build_signed_tx(
            state, signatures, signatures_len, serialized_tx, serialized_tx_len, serialized_tx_written);
}
#endif /* AMALGAMATED_BUILD */
