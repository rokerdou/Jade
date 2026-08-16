#ifndef AMALGAMATED_BUILD
#include "multisig_tx.h"

#include "normalizer.h"
#include "policy.h"
#include "script_builder.h"
#include "signing_state.h"

#include "../../../chains/bitcoin/path.h"

#include <stdlib.h>
#include <string.h>
#include <wally_map.h>
#include <wally_script.h>
#include <wally_transaction.h>

#define TREZOR_BITCOIN_SIGHASH_ALL 1U

static bool txid_to_wally_hash(const uint8_t txid[SHA256_LEN], uint8_t hash[SHA256_LEN])
{
    if (!txid || !hash) {
        return false;
    }
    for (size_t i = 0; i < SHA256_LEN; ++i) {
        hash[i] = txid[SHA256_LEN - 1U - i];
    }
    return true;
}

static bool path_from_input(const trezor_bitcoin_tx_input_t* const input, wallet_core_path_t* const path)
{
    if (!input || !path || input->address_n_len == 0 || input->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    wally_bzero(path, sizeof(*path));
    path->len = input->address_n_len;
    memcpy(path->parts, input->address_n, input->address_n_len * sizeof(input->address_n[0]));
    return true;
}

static bool redeem_script_matches_policy(const trezor_bitcoin_multisig_policy_t* const policy)
{
    if (!policy || !is_multisig(policy->variant) || policy->threshold == 0 || policy->num_pubkeys == 0
        || policy->threshold > policy->num_pubkeys || policy->num_pubkeys > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS
        || policy->redeem_script_len != 3U + (policy->num_pubkeys * (1U + EC_PUBLIC_KEY_LEN))
        || policy->redeem_script_len > sizeof(policy->redeem_script)
        || policy->redeem_script[0] != (uint8_t)(0x50U + policy->threshold)
        || policy->redeem_script[policy->redeem_script_len - 2U] != (uint8_t)(0x50U + policy->num_pubkeys)
        || policy->redeem_script[policy->redeem_script_len - 1U] != 0xae) {
        return false;
    }
    for (size_t i = 0; i < policy->num_pubkeys; ++i) {
        const size_t offset = 1U + (i * (1U + EC_PUBLIC_KEY_LEN));
        if (policy->redeem_script[offset] != EC_PUBLIC_KEY_LEN
            || memcmp(policy->redeem_script + offset + 1U, policy->pubkeys + (i * EC_PUBLIC_KEY_LEN), EC_PUBLIC_KEY_LEN)
                != 0) {
            return false;
        }
    }
    return true;
}

static bool script_hashes_match_policy(const trezor_bitcoin_multisig_policy_t* const policy)
{
    uint8_t expected_script[TREZOR_BITCOIN_MULTISIG_STANDARD_SCRIPT_PUBKEY_MAX_LEN];
    uint8_t witness_program[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    size_t expected_script_len = 0;
    size_t witness_program_len = 0;
    wally_bzero(expected_script, sizeof(expected_script));
    wally_bzero(witness_program, sizeof(witness_program));

    bool ok = false;
    if (policy->variant == MULTI_P2SH) {
        ok = policy->witness_program_len == 0
            && wally_scriptpubkey_p2sh_from_bytes(policy->redeem_script, policy->redeem_script_len,
                   WALLY_SCRIPT_HASH160, expected_script, sizeof(expected_script), &expected_script_len)
                == WALLY_OK;
    } else {
        ok = wally_witness_program_from_bytes(policy->redeem_script, policy->redeem_script_len, WALLY_SCRIPT_SHA256,
                 witness_program, sizeof(witness_program), &witness_program_len)
                == WALLY_OK
            && witness_program_len == sizeof(witness_program) && policy->witness_program_len == witness_program_len
            && memcmp(policy->witness_program, witness_program, witness_program_len) == 0;
        if (ok && policy->variant == MULTI_P2WSH) {
            memcpy(expected_script, witness_program, witness_program_len);
            expected_script_len = witness_program_len;
        } else if (ok && policy->variant == MULTI_P2WSH_P2SH) {
            ok = wally_scriptpubkey_p2sh_from_bytes(witness_program, witness_program_len, WALLY_SCRIPT_HASH160,
                     expected_script, sizeof(expected_script), &expected_script_len)
                == WALLY_OK;
        }
    }
    ok = ok && expected_script_len == policy->script_pubkey_len
        && memcmp(expected_script, policy->script_pubkey, expected_script_len) == 0;
    wally_bzero(expected_script, sizeof(expected_script));
    wally_bzero(witness_program, sizeof(witness_program));
    return ok;
}

static bool policy_matches_input(const trezor_bitcoin_signing_state_t* const state, const size_t input_index,
    const trezor_bitcoin_multisig_policy_t* const policy)
{
    if (!state || input_index >= state->inputs_len || !policy || !redeem_script_matches_policy(policy)
        || !script_hashes_match_policy(policy)) {
        return false;
    }
    const trezor_bitcoin_tx_input_t* const input = &state->inputs[input_index];
    const trezor_bitcoin_multisig_summary_t* const summary = &input->multisig;
    if (!input->has_multisig || !input->has_verified_prevout_script
        || !state->input_has_multisig_fingerprint[input_index] || summary->variant != policy->variant
        || summary->threshold != policy->threshold || summary->num_pubkeys != policy->num_pubkeys
        || summary->sorted != policy->sorted || summary->script_pubkey_len != policy->script_pubkey_len
        || summary->script_pubkey_len == 0 || summary->script_pubkey_len > sizeof(summary->script_pubkey)
        || input->verified_prevout_script_len != policy->script_pubkey_len
        || memcmp(summary->script_pubkey, policy->script_pubkey, policy->script_pubkey_len) != 0
        || memcmp(input->verified_prevout_script, policy->script_pubkey, policy->script_pubkey_len) != 0
        || memcmp(state->input_multisig_fingerprints[input_index], policy->fingerprint, SHA256_LEN) != 0) {
        return false;
    }
    if (policy->variant == MULTI_P2SH) {
        return policy->witness_program_len == 0 && input->script_type == BITCOIN_MULTISIG_SPENDMULTISIG;
    }
    return policy->witness_program_len == WALLY_SCRIPTPUBKEY_P2WSH_LEN && policy->witness_program[0] == 0
        && policy->witness_program[1] == SHA256_LEN
        && (policy->variant == MULTI_P2WSH ? input->script_type == BITCOIN_P2WPKH_SPENDWITNESS
                    && policy->script_pubkey_len == policy->witness_program_len
                    && memcmp(policy->script_pubkey, policy->witness_program, policy->witness_program_len) == 0
                                           : input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS);
}

static bool validate_state_and_policies(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_multisig_policy_t* const* const policies, const size_t policies_len)
{
    if (!state || !policies || policies_len == 0 || policies_len != state->inputs_len
        || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count
        || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX || state->outputs_len == 0
        || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX || !state->request.serialize
        || !trezor_bitcoin_signing_ready(state)) {
        return false;
    }
    bitcoin_confirm_request_t confirm;
    if (!trezor_bitcoin_signing_to_multisig_confirm_request(state, &confirm)) {
        return false;
    }
    const script_variant_t variant = policies[0] ? policies[0]->variant : GREEN;
    for (size_t i = 0; i < policies_len; ++i) {
        if (!policies[i] || policies[i]->variant != variant || !policy_matches_input(state, i, policies[i])) {
            return false;
        }
    }
    return state->total_input >= state->total_output && state->fee == state->total_input - state->total_output
        && confirm.amount > 0 && confirm.fee == state->fee;
}

static bool add_unsigned_inputs(struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state)
{
    for (size_t i = 0; tx && state && i < state->inputs_len; ++i) {
        uint8_t hash[SHA256_LEN];
        wally_bzero(hash, sizeof(hash));
        const bool ok = txid_to_wally_hash(state->inputs[i].prev_hash, hash)
            && wally_tx_add_raw_input(
                   tx, hash, sizeof(hash), state->inputs[i].prev_index, state->inputs[i].sequence, NULL, 0, NULL, 0)
                == WALLY_OK;
        wally_bzero(hash, sizeof(hash));
        if (!ok) {
            return false;
        }
    }
    return tx && state;
}

static bool add_outputs(
    struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state, const trezor_bitcoin_coin_t coin)
{
    for (size_t i = 0; tx && state && i < state->outputs_len; ++i) {
        uint8_t script[TREZOR_BITCOIN_MULTISIG_STANDARD_SCRIPT_PUBKEY_MAX_LEN];
        size_t script_len = 0;
        wally_bzero(script, sizeof(script));
        const bool ok
            = trezor_bitcoin_script_builder_output_script(&state->outputs[i], coin, script, sizeof(script), &script_len)
            && wally_tx_add_raw_output(tx, state->outputs[i].amount, script, script_len, 0) == WALLY_OK;
        wally_bzero(script, sizeof(script));
        if (!ok) {
            return false;
        }
    }
    return tx && state;
}

bool trezor_bitcoin_multisig_build_hash(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_multisig_policy_t* const* const policies, const size_t policies_len, const size_t input_index,
    wallet_core_path_t* const path, uint8_t* const digest, const size_t digest_len)
{
    if (!path || !digest || digest_len != SHA256_LEN || input_index >= policies_len
        || !validate_state_and_policies(state, policies, policies_len)) {
        return false;
    }

    bool ok = false;
    struct wally_tx* tx = NULL;
    struct wally_map values;
    wallet_core_path_t local_path;
    uint8_t local_pubkey[EC_PUBLIC_KEY_LEN];
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    wally_bzero(&values, sizeof(values));
    wally_bzero(&local_path, sizeof(local_path));
    wally_bzero(local_pubkey, sizeof(local_pubkey));
    wally_bzero(digest, digest_len);

    const trezor_bitcoin_multisig_policy_t* const policy = policies[input_index];
    ok = trezor_bitcoin_policy_signing_coin(state, &coin) && path_from_input(&state->inputs[input_index], &local_path)
        && wallet_core_get_public_key(&local_path, WALLET_CORE_PUBKEY_COMPRESSED, local_pubkey, sizeof(local_pubkey))
        && trezor_bitcoin_multisig_policy_contains_pubkey(policy, local_pubkey, sizeof(local_pubkey))
        && wally_tx_init_alloc(
               state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx && add_unsigned_inputs(tx, state) && add_outputs(tx, state, coin)
        && wally_map_init(state->inputs_len, NULL, &values) == WALLY_OK;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        ok = wally_map_add_integer(
                 &values, (uint32_t)i, (const uint8_t*)&state->inputs[i].amount, sizeof(state->inputs[i].amount))
            == WALLY_OK;
    }
    const uint32_t signature_type = policy->variant == MULTI_P2SH ? WALLY_SIGTYPE_PRE_SW : WALLY_SIGTYPE_SW_V0;
    ok = ok
        && wally_tx_get_input_signature_hash(tx, input_index, NULL, NULL, &values, policy->redeem_script,
               policy->redeem_script_len, 0, WALLY_NO_CODESEPARATOR, NULL, 0, NULL, 0, TREZOR_BITCOIN_SIGHASH_ALL,
               signature_type, NULL, digest, digest_len)
            == WALLY_OK;
    if (ok) {
        *path = local_path;
    }

    if (tx) {
        wally_tx_free(tx);
    }
    wally_map_clear(&values);
    wally_bzero(&local_path, sizeof(local_path));
    wally_bzero(local_pubkey, sizeof(local_pubkey));
    if (!ok) {
        wally_bzero(digest, digest_len);
    }
    return ok;
}

static bool build_unlocking_data(const trezor_bitcoin_multisig_unlock_t* const unlock, uint8_t** const script_sig,
    size_t* const script_sig_len, struct wally_tx_witness_stack** const witness)
{
    if (!unlock || !unlock->policy || !unlock->compact_signatures || !script_sig || !script_sig_len || !witness
        || unlock->signatures_count != unlock->policy->threshold
        || unlock->compact_signatures_len != unlock->signatures_count * EC_SIGNATURE_LEN) {
        return false;
    }
    *script_sig = NULL;
    *script_sig_len = 0;
    *witness = NULL;

    uint32_t sighashes[TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS];
    for (size_t i = 0; i < unlock->signatures_count; ++i) {
        sighashes[i] = TREZOR_BITCOIN_SIGHASH_ALL;
    }

    if (unlock->policy->variant == MULTI_P2SH) {
        uint8_t required_probe = 0;
        size_t required = 0;
        if (wally_scriptsig_multisig_from_bytes(unlock->policy->redeem_script, unlock->policy->redeem_script_len,
                unlock->compact_signatures, unlock->compact_signatures_len, sighashes, unlock->signatures_count, 0,
                &required_probe, sizeof(required_probe), &required)
                != WALLY_OK
            || required == 0 || required > TREZOR_BITCOIN_SIGNED_TX_MAX_LEN) {
            return false;
        }
        *script_sig = malloc(required);
        if (!*script_sig) {
            return false;
        }
        const bool ok
            = wally_scriptsig_multisig_from_bytes(unlock->policy->redeem_script, unlock->policy->redeem_script_len,
                  unlock->compact_signatures, unlock->compact_signatures_len, sighashes, unlock->signatures_count, 0,
                  *script_sig, required, script_sig_len)
                == WALLY_OK
            && *script_sig_len == required;
        if (!ok) {
            wally_bzero(*script_sig, required);
            free(*script_sig);
            *script_sig = NULL;
            *script_sig_len = 0;
        }
        return ok;
    }

    if (wally_witness_multisig_from_bytes(unlock->policy->redeem_script, unlock->policy->redeem_script_len,
            unlock->compact_signatures, unlock->compact_signatures_len, sighashes, unlock->signatures_count, 0, witness)
        != WALLY_OK) {
        return false;
    }
    if (unlock->policy->variant == MULTI_P2WSH_P2SH) {
        *script_sig_len = 1U + unlock->policy->witness_program_len;
        *script_sig = malloc(*script_sig_len);
        if (!*script_sig) {
            wally_tx_witness_stack_free(*witness);
            *witness = NULL;
            *script_sig_len = 0;
            return false;
        }
        (*script_sig)[0] = (uint8_t)unlock->policy->witness_program_len;
        memcpy(*script_sig + 1U, unlock->policy->witness_program, unlock->policy->witness_program_len);
    }
    return true;
}

bool trezor_bitcoin_multisig_build_signed_tx(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_multisig_unlock_t* const unlocks, const size_t unlocks_len, uint8_t* const serialized_tx,
    const size_t serialized_tx_len, size_t* const serialized_tx_written)
{
    if (!unlocks || !serialized_tx || !serialized_tx_written || unlocks_len == 0
        || unlocks_len > TREZOR_BITCOIN_TX_INPUTS_MAX) {
        return false;
    }
    const trezor_bitcoin_multisig_policy_t* policies[TREZOR_BITCOIN_TX_INPUTS_MAX];
    for (size_t i = 0; i < unlocks_len; ++i) {
        policies[i] = unlocks[i].policy;
    }
    if (!validate_state_and_policies(state, policies, unlocks_len)) {
        return false;
    }

    bool ok = false;
    struct wally_tx* tx = NULL;
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    uint8_t* script_sigs[TREZOR_BITCOIN_TX_INPUTS_MAX] = { 0 };
    size_t script_sig_lens[TREZOR_BITCOIN_TX_INPUTS_MAX] = { 0 };
    struct wally_tx_witness_stack* witnesses[TREZOR_BITCOIN_TX_INPUTS_MAX] = { 0 };
    *serialized_tx_written = 0;

    ok = trezor_bitcoin_policy_signing_coin(state, &coin)
        && wally_tx_init_alloc(
               state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        uint8_t hash[SHA256_LEN];
        wally_bzero(hash, sizeof(hash));
        ok = build_unlocking_data(&unlocks[i], &script_sigs[i], &script_sig_lens[i], &witnesses[i])
            && txid_to_wally_hash(state->inputs[i].prev_hash, hash)
            && wally_tx_add_raw_input(tx, hash, sizeof(hash), state->inputs[i].prev_index, state->inputs[i].sequence,
                   script_sigs[i], script_sig_lens[i], witnesses[i], 0)
                == WALLY_OK;
        wally_bzero(hash, sizeof(hash));
    }
    const bool use_witness = policies[0]->variant != MULTI_P2SH;
    ok = ok && add_outputs(tx, state, coin)
        && wally_tx_to_bytes(
               tx, use_witness ? WALLY_TX_FLAG_USE_WITNESS : 0, serialized_tx, serialized_tx_len, serialized_tx_written)
            == WALLY_OK;

    if (tx) {
        wally_tx_free(tx);
    }
    for (size_t i = 0; i < unlocks_len; ++i) {
        if (script_sigs[i]) {
            wally_bzero(script_sigs[i], script_sig_lens[i]);
            free(script_sigs[i]);
        }
        if (witnesses[i]) {
            wally_tx_witness_stack_free(witnesses[i]);
        }
    }
    if (!ok) {
        wally_bzero(serialized_tx, serialized_tx_len);
        *serialized_tx_written = 0;
    }
    return ok;
}
#endif /* AMALGAMATED_BUILD */
