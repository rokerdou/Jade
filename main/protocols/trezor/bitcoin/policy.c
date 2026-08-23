#ifndef AMALGAMATED_BUILD
#include "policy.h"

#include "script_policy.h"
#include "signing_state.h"
#include "../../../chains/bitcoin/path.h"
#include "../../../chains/path.h"
#include "../trace.h"

#include <string.h>
#include <wally_crypto.h>
#include <wally_script.h>

#define TREZOR_BITCOIN_P2WPKH_TX_OVERHEAD_VBYTES 11U
#define TREZOR_BITCOIN_P2PKH_TX_OVERHEAD_VBYTES 10U
#define TREZOR_BITCOIN_P2PKH_INPUT_VBYTES 148U
#define TREZOR_BITCOIN_P2WPKH_INPUT_VBYTES 68U
#define TREZOR_BITCOIN_P2SH_P2WPKH_INPUT_VBYTES 91U
#define TREZOR_BITCOIN_P2PKH_OUTPUT_VBYTES 34U
#define TREZOR_BITCOIN_P2WPKH_OUTPUT_VBYTES 31U
#define TREZOR_BITCOIN_P2SH_P2WPKH_OUTPUT_VBYTES 32U
#define TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE 1000U
#define TREZOR_BITCOIN_MULTISIG_MAX_DER_SIGNATURE_LEN 73U
#define TREZOR_BITCOIN_P2SH_SCRIPT_LEN 23U

#define BTC_POLICY_TRACE_STAGE(stage) trezor_trace_set_stage(stage)
#define BTC_POLICY_TRACE_NOTE(...) trezor_trace_set_note(__VA_ARGS__)
#define BTC_POLICY_TRACE_STAGE_NOTE(stage, ...) \
    do {                                        \
        BTC_POLICY_TRACE_STAGE(stage);          \
        BTC_POLICY_TRACE_NOTE(__VA_ARGS__);     \
    } while (0)

bool trezor_bitcoin_coin_from_name(const char* const name, trezor_bitcoin_coin_t* const coin)
{
    if (!name || !coin) {
        return false;
    }
    if (strcmp(name, "Bitcoin") == 0) {
        *coin = TREZOR_BITCOIN_COIN_MAINNET;
        return true;
    }
    if (strcmp(name, "Testnet") == 0) {
        *coin = TREZOR_BITCOIN_COIN_TESTNET;
        return true;
    }
    return false;
}

bool trezor_bitcoin_coin_is_testnet(const trezor_bitcoin_coin_t coin)
{
    return coin == TREZOR_BITCOIN_COIN_TESTNET;
}

const char* trezor_bitcoin_coin_segwit_hrp(const trezor_bitcoin_coin_t coin)
{
    return trezor_bitcoin_coin_is_testnet(coin) ? "tb" : "bc";
}

static bool trezor_bitcoin_policy_add_u64(uint64_t* const total, const uint64_t value)
{
    if (!total || value > UINT64_MAX - *total) {
        return false;
    }
    *total += value;
    return true;
}

static uint64_t trezor_bitcoin_policy_compact_size_len(const uint64_t value)
{
    if (value < 0xfdU) {
        return 1U;
    }
    if (value <= UINT16_MAX) {
        return 3U;
    }
    if (value <= UINT32_MAX) {
        return 5U;
    }
    return 9U;
}

static bool trezor_bitcoin_policy_multisig_redeem_script_len(
    const trezor_bitcoin_multisig_summary_t* const multisig, uint64_t* const redeem_script_len)
{
    if (!multisig || !redeem_script_len || multisig->threshold == 0 || multisig->num_pubkeys == 0
        || multisig->threshold > multisig->num_pubkeys
        || multisig->num_pubkeys > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS) {
        return false;
    }
    *redeem_script_len = 1U + ((uint64_t)multisig->num_pubkeys * (1U + EC_PUBLIC_KEY_LEN)) + 1U + 1U;
    return true;
}

static uint64_t trezor_bitcoin_policy_pushdata_len(const uint64_t payload_len)
{
    if (payload_len <= 75U) {
        return 1U;
    }
    if (payload_len <= UINT8_MAX) {
        return 2U;
    }
    if (payload_len <= UINT16_MAX) {
        return 3U;
    }
    return 5U;
}

static bool trezor_bitcoin_policy_estimate_multisig_input_vbytes(
    const trezor_bitcoin_tx_input_t* const input, uint64_t* const vbytes)
{
    if (!input || !vbytes || !input->has_multisig) {
        return false;
    }

    uint64_t redeem_script_len = 0;
    if (!trezor_bitcoin_policy_multisig_redeem_script_len(&input->multisig, &redeem_script_len)) {
        return false;
    }
    const uint64_t signatures_len = (uint64_t)input->multisig.threshold * (1U + TREZOR_BITCOIN_MULTISIG_MAX_DER_SIGNATURE_LEN);
    const uint64_t witness_stack_len = 1U + 1U + signatures_len + trezor_bitcoin_policy_pushdata_len(redeem_script_len)
        + redeem_script_len;

    if (input->multisig.variant == MULTI_P2SH) {
        const uint64_t script_sig_len = witness_stack_len;
        *vbytes = 32U + 4U + trezor_bitcoin_policy_compact_size_len(script_sig_len) + script_sig_len + 4U;
        return true;
    }
    if (input->multisig.variant == MULTI_P2WSH) {
        *vbytes = 32U + 4U + 1U + 4U + ((witness_stack_len + 3U) / 4U);
        return true;
    }
    if (input->multisig.variant == MULTI_P2WSH_P2SH) {
        const uint64_t nested_script_sig_len = 1U + WALLY_SCRIPTPUBKEY_P2WSH_LEN;
        *vbytes = 32U + 4U + trezor_bitcoin_policy_compact_size_len(nested_script_sig_len) + nested_script_sig_len
            + 4U + ((witness_stack_len + 3U) / 4U);
        return true;
    }
    return false;
}

static bool trezor_bitcoin_policy_estimate_multisig_output_vbytes(
    const trezor_bitcoin_tx_output_t* const output, uint64_t* const vbytes)
{
    if (!output || !vbytes || !output->has_multisig) {
        return false;
    }
    if (output->multisig.variant == MULTI_P2WSH) {
        *vbytes = 8U + 1U + WALLY_SCRIPTPUBKEY_P2WSH_LEN;
        return true;
    }
    if (output->multisig.variant == MULTI_P2SH || output->multisig.variant == MULTI_P2WSH_P2SH) {
        *vbytes = 8U + 1U + TREZOR_BITCOIN_P2SH_SCRIPT_LEN;
        return true;
    }
    return false;
}

bool trezor_bitcoin_policy_calculate_totals(trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count) {
        return false;
    }

    state->total_input = 0;
    state->total_output = 0;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        if (!state->inputs[i].has_amount
            || !trezor_bitcoin_policy_add_u64(&state->total_input, state->inputs[i].amount)) {
            return false;
        }
    }
    for (size_t i = 0; i < state->outputs_len; ++i) {
        if (!state->outputs[i].has_amount
            || !trezor_bitcoin_policy_add_u64(&state->total_output, state->outputs[i].amount)) {
            return false;
        }
    }
    if (state->total_output > state->total_input) {
        return false;
    }
    state->fee = state->total_input - state->total_output;
    state->fee_rate_sats_per_vbyte = 0;
    return true;
}

bool trezor_bitcoin_policy_estimate_p2wpkh_fee_rate(trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len == 0 || state->outputs_len == 0
        || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX) {
        return false;
    }

    const uint64_t vbytes = TREZOR_BITCOIN_P2WPKH_TX_OVERHEAD_VBYTES
        + (state->inputs_len * TREZOR_BITCOIN_P2WPKH_INPUT_VBYTES)
        + (state->outputs_len * TREZOR_BITCOIN_P2WPKH_OUTPUT_VBYTES);
    if (vbytes == 0 || state->fee > UINT64_MAX - (vbytes - 1U)) {
        return false;
    }

    state->fee_rate_sats_per_vbyte = (state->fee + vbytes - 1U) / vbytes;
    return state->fee_rate_sats_per_vbyte <= TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE;
}

bool trezor_bitcoin_policy_estimate_basic_fee_rate(trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len == 0 || state->outputs_len == 0
        || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX) {
        return false;
    }

    const uint32_t input_script_type = state->inputs[0].script_type;
    uint64_t vbytes = input_script_type == BITCOIN_P2PKH_SPENDADDRESS ? TREZOR_BITCOIN_P2PKH_TX_OVERHEAD_VBYTES
                                                                       : TREZOR_BITCOIN_P2WPKH_TX_OVERHEAD_VBYTES;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        uint64_t input_vbytes = 0;
        if (state->inputs[i].has_multisig) {
            if (!trezor_bitcoin_policy_estimate_multisig_input_vbytes(&state->inputs[i], &input_vbytes)) {
                return false;
            }
        } else {
            input_vbytes = state->inputs[i].script_type == BITCOIN_P2PKH_SPENDADDRESS
                ? TREZOR_BITCOIN_P2PKH_INPUT_VBYTES
                : state->inputs[i].script_type == BITCOIN_P2WPKH_SPENDWITNESS
                ? TREZOR_BITCOIN_P2WPKH_INPUT_VBYTES
                : state->inputs[i].script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
                ? TREZOR_BITCOIN_P2SH_P2WPKH_INPUT_VBYTES
                : 0;
        }
        if (input_vbytes == 0 || input_vbytes > UINT64_MAX - vbytes) {
            return false;
        }
        vbytes += input_vbytes;
    }
    const uint32_t account = state->inputs[0].address_n_len > 2 ? state->inputs[0].address_n[2] : 0;
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!trezor_bitcoin_policy_signing_coin(state, &coin)) {
        return false;
    }
    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    for (size_t i = 0; i < state->outputs_len; ++i) {
        uint64_t output_vbytes = state->outputs[i].has_address ? TREZOR_BITCOIN_P2PKH_OUTPUT_VBYTES
                                                                : TREZOR_BITCOIN_P2WPKH_OUTPUT_VBYTES;
        if (state->outputs[i].has_multisig
            && !trezor_bitcoin_policy_estimate_multisig_output_vbytes(&state->outputs[i], &output_vbytes)) {
            return false;
        }
        if (!state->outputs[i].has_address) {
            if (input_script_type == BITCOIN_P2PKH_SPENDADDRESS
                && bitcoin_path_is_p2pkh_change(
                    state->outputs[i].address_n, state->outputs[i].address_n_len, testnet, account)) {
                output_vbytes = TREZOR_BITCOIN_P2PKH_OUTPUT_VBYTES;
            } else if (input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
                && bitcoin_path_is_p2sh_p2wpkh_change(
                    state->outputs[i].address_n, state->outputs[i].address_n_len, testnet, account)) {
                output_vbytes = TREZOR_BITCOIN_P2SH_P2WPKH_OUTPUT_VBYTES;
            }
        }
        if (output_vbytes > UINT64_MAX - vbytes) {
            return false;
        }
        vbytes += output_vbytes;
    }
    if (vbytes == 0 || state->fee > UINT64_MAX - (vbytes - 1U)) {
        return false;
    }

    state->fee_rate_sats_per_vbyte = (state->fee + vbytes - 1U) / vbytes;
    return state->fee_rate_sats_per_vbyte <= TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE;
}

bool trezor_bitcoin_policy_signing_coin(
    const trezor_bitcoin_signing_state_t* const state, trezor_bitcoin_coin_t* const coin)
{
    return state && state->request.has_coin_name && trezor_bitcoin_coin_from_name(state->request.coin_name, coin);
}

bool trezor_bitcoin_policy_has_multisig(const trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX
        || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX) {
        return false;
    }
    for (size_t i = 0; i < state->inputs_len; ++i) {
        if (state->inputs[i].has_multisig) {
            return true;
        }
    }
    for (size_t i = 0; i < state->outputs_len; ++i) {
        if (state->outputs[i].has_multisig) {
            return true;
        }
    }
    return false;
}

bool trezor_bitcoin_policy_common_sequence(const trezor_bitcoin_signing_state_t* const state, uint32_t* const sequence)
{
    if (!state || !sequence || state->inputs_len == 0 || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX) {
        return false;
    }

    const uint32_t common_sequence = state->inputs[0].sequence;
    for (size_t i = 1; i < state->inputs_len; ++i) {
        if (state->inputs[i].sequence != common_sequence) {
            return false;
        }
    }
    *sequence = common_sequence;
    return true;
}

bool trezor_bitcoin_policy_multisig_output_matches_inputs(
    const trezor_bitcoin_signing_state_t* const state, const size_t output_index)
{
    if (!state || state->inputs_len == 0 || output_index >= state->outputs_len
        || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX
        || !state->outputs[output_index].has_multisig || !state->output_has_multisig_fingerprint[output_index]) {
        return false;
    }

    trezor_bitcoin_multisig_matcher_t matcher;
    trezor_bitcoin_multisig_matcher_reset(&matcher);
    for (size_t i = 0; i < state->inputs_len; ++i) {
        if (!state->inputs[i].has_multisig || !state->input_has_multisig_fingerprint[i]
            || !trezor_bitcoin_multisig_matcher_add(
                &matcher, state->input_multisig_fingerprints[i], sizeof(state->input_multisig_fingerprints[i]))) {
            trezor_bitcoin_multisig_matcher_reset(&matcher);
            return false;
        }
    }

    const bool ok = trezor_bitcoin_multisig_matcher_output_matches(&matcher,
        state->output_multisig_fingerprints[output_index], sizeof(state->output_multisig_fingerprints[output_index]));
    trezor_bitcoin_multisig_matcher_reset(&matcher);
    return ok;
}

static bool trezor_bitcoin_policy_multisig_path_type(
    const script_variant_t variant, bitcoin_multisig_path_type_t* const path_type)
{
    if (!path_type) {
        return false;
    }
    if (variant == MULTI_P2SH) {
        *path_type = BITCOIN_MULTISIG_PATH_P2SH;
        return true;
    }
    if (variant == MULTI_P2WSH_P2SH) {
        *path_type = BITCOIN_MULTISIG_PATH_P2SH_P2WSH;
        return true;
    }
    if (variant == MULTI_P2WSH) {
        *path_type = BITCOIN_MULTISIG_PATH_P2WSH;
        return true;
    }
    return false;
}

bool trezor_bitcoin_policy_multisig_preview(
    const trezor_bitcoin_signing_state_t* const state, trezor_bitcoin_multisig_preview_t* const preview)
{
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!state || !preview || !trezor_bitcoin_signing_ready(state) || state->inputs_len == 0 || state->outputs_len == 0
        || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count
        || state->inputs_len > TREZOR_BITCOIN_TX_INPUTS_MAX || state->outputs_len > TREZOR_BITCOIN_TX_OUTPUTS_MAX
        || !state->request.serialize
        || !trezor_bitcoin_policy_signing_coin(state, &coin)
        || state->fee_rate_sats_per_vbyte > TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE) {
        return false;
    }
    uint32_t common_sequence = 0;
    if (!trezor_bitcoin_policy_common_sequence(state, &common_sequence)) {
        return false;
    }

    wally_bzero(preview, sizeof(*preview));
    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    const trezor_bitcoin_tx_input_t* const first_input = &state->inputs[0];
    bitcoin_multisig_path_type_t path_type = BITCOIN_MULTISIG_PATH_P2SH;
    if (!first_input->has_multisig
        || !trezor_bitcoin_policy_multisig_path_type(first_input->multisig.variant, &path_type)) {
        return false;
    }
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        if (!input->has_multisig || !input->has_prev_hash || !input->has_prev_index || !input->has_amount
            || !input->has_verified_prevout_script || !state->input_has_multisig_fingerprint[i]
            || input->multisig.variant != first_input->multisig.variant
            || !bitcoin_path_is_multisig_signing(input->address_n, input->address_n_len, testnet, path_type)
            || !bitcoin_path_multisig_wallet_matches(
                first_input->address_n, first_input->address_n_len, input->address_n, input->address_n_len)
            || input->verified_prevout_script_len == 0
            || !trezor_bitcoin_script_policy_prevout_matches_input(
                input, coin, input->verified_prevout_script, input->verified_prevout_script_len)) {
            wally_bzero(preview, sizeof(*preview));
            return false;
        }
    }

    for (size_t i = 0; i < state->outputs_len; ++i) {
        const trezor_bitcoin_tx_output_t* const output = &state->outputs[i];
        if (!output->has_amount) {
            wally_bzero(preview, sizeof(*preview));
            return false;
        }
        if (output->has_address) {
            if (output->has_multisig || output->address_n_len != 0 || output->script_type != BITCOIN_PAYTOADDRESS) {
                wally_bzero(preview, sizeof(*preview));
                return false;
            }
            if (preview->external_outputs == 0) {
                preview->first_external_output_index = i;
            }
            ++preview->external_outputs;
            if (!trezor_bitcoin_policy_add_u64(&preview->external_amount, output->amount)) {
                wally_bzero(preview, sizeof(*preview));
                return false;
            }
        } else {
            if (!output->has_multisig || output->address_n_len == 0 || output->script_type != BITCOIN_PAYTOMULTISIG
                || output->multisig.variant != first_input->multisig.variant
                || !bitcoin_path_is_multisig_change_for_input(first_input->address_n, first_input->address_n_len,
                    output->address_n, output->address_n_len, testnet, path_type)
                || !trezor_bitcoin_policy_multisig_output_matches_inputs(state, i)
                || !trezor_bitcoin_policy_add_u64(&preview->change_amount, output->amount)) {
                wally_bzero(preview, sizeof(*preview));
                return false;
            }
        }
    }

    if (preview->external_outputs != 1 || preview->external_amount == 0
        || preview->external_amount > state->total_output || preview->change_amount > state->total_output
        || preview->external_amount != state->total_output - preview->change_amount) {
        wally_bzero(preview, sizeof(*preview));
        return false;
    }
    return true;
}

static bool trezor_bitcoin_policy_input_is_supported_without_prev_tx_verification(
    const trezor_bitcoin_tx_input_t* const input, const bool testnet)
{
    return input && !input->has_multisig && input->script_type == BITCOIN_P2WPKH_SPENDWITNESS && input->has_prev_hash
        && input->has_prev_index && input->has_amount
        && bitcoin_path_is_p2wpkh_signing(input->address_n, input->address_n_len, testnet);
}

static bool trezor_bitcoin_policy_input_is_p2sh_p2wpkh_verified(
    const trezor_bitcoin_tx_input_t* const input, const bool testnet)
{
    return input && !input->has_multisig && input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
        && input->has_prev_hash
        && input->has_prev_index && input->has_amount && input->has_verified_prevout_script
        && input->verified_prevout_script_len == 23
        && bitcoin_path_is_p2sh_p2wpkh_signing(input->address_n, input->address_n_len, testnet);
}

static bool trezor_bitcoin_policy_input_is_p2pkh_verified(
    const trezor_bitcoin_tx_input_t* const input, const bool testnet)
{
    return input && !input->has_multisig && input->script_type == BITCOIN_P2PKH_SPENDADDRESS && input->has_prev_hash
        && input->has_prev_index && input->has_amount && input->has_verified_prevout_script
        && input->verified_prevout_script_len == WALLY_SCRIPTPUBKEY_P2PKH_LEN
        && bitcoin_path_is_p2pkh_signing(input->address_n, input->address_n_len, testnet);
}

static uint32_t trezor_bitcoin_policy_change_branch_for_trace(const uint32_t* const address_n, const size_t address_n_len)
{
    return address_n && address_n_len >= 2 ? address_n[address_n_len - 2U] : UINT32_MAX;
}

static void trezor_bitcoin_policy_trace_input_shape(
    const char* const stage, const size_t index, const trezor_bitcoin_tx_input_t* const input)
{
    if (!input) {
        BTC_POLICY_TRACE_STAGE_NOTE(stage, "in=%lu null", (unsigned long)index);
        return;
    }
    BTC_POLICY_TRACE_STAGE_NOTE(stage, "in=%lu st=%lu path=%lu prev=%u idx=%u amt=%u prevout=%u multi=%u",
        (unsigned long)index, (unsigned long)input->script_type, (unsigned long)input->address_n_len,
        input->has_prev_hash ? 1U : 0U, input->has_prev_index ? 1U : 0U, input->has_amount ? 1U : 0U,
        input->has_verified_prevout_script ? 1U : 0U, input->has_multisig ? 1U : 0U);
}

static void trezor_bitcoin_policy_trace_output_shape(
    const char* const stage, const size_t index, const trezor_bitcoin_tx_output_t* const output)
{
    if (!output) {
        BTC_POLICY_TRACE_STAGE_NOTE(stage, "out=%lu null", (unsigned long)index);
        return;
    }
    const uint32_t branch = trezor_bitcoin_policy_change_branch_for_trace(output->address_n, output->address_n_len);
    BTC_POLICY_TRACE_STAGE_NOTE(stage, "out=%lu addr=%u path=%lu st=%lu multi=%u amt=%u sats=%llu branch=%lu",
        (unsigned long)index, output->has_address ? 1U : 0U, (unsigned long)output->address_n_len,
        (unsigned long)output->script_type, output->has_multisig ? 1U : 0U, output->has_amount ? 1U : 0U,
        (unsigned long long)(output->has_amount ? output->amount : 0U), (unsigned long)branch);
}

static bool trezor_bitcoin_policy_output_script_is_external_address(const uint32_t script_type)
{
    return script_type == BITCOIN_PAYTOADDRESS || script_type == BITCOIN_PAYTOP2SHWITNESS
        || script_type == BITCOIN_PAYTOWITNESS;
}

static bool trezor_bitcoin_policy_output_script_matches_change(
    const uint32_t input_script_type, const uint32_t output_script_type)
{
    if (input_script_type == BITCOIN_P2PKH_SPENDADDRESS) {
        return output_script_type == BITCOIN_PAYTOADDRESS;
    }
    if (input_script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        return output_script_type == BITCOIN_PAYTOWITNESS;
    }
    if (input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        return output_script_type == BITCOIN_PAYTOP2SHWITNESS;
    }
    return false;
}

static bool trezor_bitcoin_policy_expected_change_purpose(
    const uint32_t input_script_type, uint32_t* const purpose)
{
    if (!purpose) {
        return false;
    }
    if (input_script_type == BITCOIN_P2PKH_SPENDADDRESS) {
        *purpose = 44;
        return true;
    }
    if (input_script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        *purpose = 84;
        return true;
    }
    if (input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        *purpose = 49;
        return true;
    }
    return false;
}

static void trezor_bitcoin_policy_trace_change_path_mismatch(const size_t index,
    const trezor_bitcoin_tx_output_t* const output, const uint32_t input_script_type, const bool testnet,
    const uint32_t account)
{
    uint32_t expected_purpose = 0;
    const uint32_t expected_coin = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    if (!output || !trezor_bitcoin_policy_expected_change_purpose(input_script_type, &expected_purpose)) {
        trezor_bitcoin_policy_trace_output_shape("btcpol:change_bad", index, output);
        return;
    }
    if (output->address_n_len != 5) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_len", "out=%lu path=%lu expected=5", (unsigned long)index,
            (unsigned long)output->address_n_len);
        return;
    }
    if (output->address_n[0] != chain_path_harden(expected_purpose)) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_purpose", "out=%lu got=%lu expected=%lu", (unsigned long)index,
            (unsigned long)chain_path_unharden(output->address_n[0]), (unsigned long)expected_purpose);
        return;
    }
    if (output->address_n[1] != chain_path_harden(expected_coin)) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_coin", "out=%lu got=%lu expected=%lu", (unsigned long)index,
            (unsigned long)chain_path_unharden(output->address_n[1]), (unsigned long)expected_coin);
        return;
    }
    if (output->address_n[2] != account) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_acct", "out=%lu got=%lu expected=%lu", (unsigned long)index,
            (unsigned long)chain_path_unharden(output->address_n[2]), (unsigned long)chain_path_unharden(account));
        return;
    }
    if (output->address_n[3] > 1) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_branch", "out=%lu got=%lu max=1", (unsigned long)index,
            (unsigned long)output->address_n[3]);
        return;
    }
    if (output->address_n[4] > 1000000U) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:change_index", "out=%lu got=%lu max=1000000", (unsigned long)index,
            (unsigned long)output->address_n[4]);
        return;
    }
    trezor_bitcoin_policy_trace_output_shape("btcpol:change_bad", index, output);
}

bool trezor_bitcoin_policy_is_p2wpkh_basic(const trezor_bitcoin_signing_state_t* const state)
{
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!state || !trezor_bitcoin_signing_ready(state) || state->inputs_len == 0 || state->outputs_len == 0
        || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count
        || !state->request.serialize
        || !trezor_bitcoin_policy_signing_coin(state, &coin)
        || state->fee_rate_sats_per_vbyte > TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE) {
        return false;
    }
    uint32_t common_sequence = 0;
    if (!trezor_bitcoin_policy_common_sequence(state, &common_sequence)) {
        return false;
    }

    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    uint32_t account = 0;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        if (!trezor_bitcoin_policy_input_is_supported_without_prev_tx_verification(input, testnet)) {
            return false;
        }
        if (input->address_n_len <= 2) {
            return false;
        }
        if (i == 0) {
            account = input->address_n[2];
        } else if (input->address_n[2] != account) {
            return false;
        }
    }

    size_t external_outputs = 0;
    for (size_t i = 0; i < state->outputs_len; ++i) {
        const trezor_bitcoin_tx_output_t* const output = &state->outputs[i];
        if (!output->has_amount || output->has_multisig
            || !trezor_bitcoin_policy_output_script_is_external_address(output->script_type)) {
            return false;
        }
        if (output->has_address) {
            ++external_outputs;
            if (output->address_n_len != 0) {
                return false;
            }
        } else if (!trezor_bitcoin_policy_output_script_matches_change(BITCOIN_P2WPKH_SPENDWITNESS, output->script_type)
            || !bitcoin_path_is_p2wpkh_internal(output->address_n, output->address_n_len, testnet, account)) {
            return false;
        }
    }
    return external_outputs == 1 && state->total_input >= state->total_output;
}

bool trezor_bitcoin_policy_is_basic(const trezor_bitcoin_signing_state_t* const state)
{
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!state) {
        BTC_POLICY_TRACE_STAGE("btcpol:null");
        return false;
    }
    if (!trezor_bitcoin_signing_ready(state)) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:not_ready", "ready=0 in=%lu/%lu out=%lu/%lu",
            (unsigned long)state->inputs_len,
            (unsigned long)state->request.inputs_count, (unsigned long)state->outputs_len,
            (unsigned long)state->request.outputs_count);
        return false;
    }
    if (state->inputs_len == 0 || state->outputs_len == 0) {
        BTC_POLICY_TRACE_STAGE_NOTE(
            "btcpol:empty", "empty in=%lu out=%lu", (unsigned long)state->inputs_len,
            (unsigned long)state->outputs_len);
        return false;
    }
    if (state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:count_bad", "count in=%lu/%lu out=%lu/%lu",
            (unsigned long)state->inputs_len,
            (unsigned long)state->request.inputs_count, (unsigned long)state->outputs_len,
            (unsigned long)state->request.outputs_count);
        return false;
    }
    if (!state->request.serialize) {
        BTC_POLICY_TRACE_STAGE("btcpol:no_serialize");
        return false;
    }
    if (!trezor_bitcoin_policy_signing_coin(state, &coin)) {
        BTC_POLICY_TRACE_STAGE("btcpol:coin_bad");
        return false;
    }
    if (state->fee_rate_sats_per_vbyte > TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:fee_high", "fee_rate=%llu max=%lu",
            (unsigned long long)state->fee_rate_sats_per_vbyte,
            (unsigned long)TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE);
        return false;
    }
    uint32_t common_sequence = 0;
    if (!trezor_bitcoin_policy_common_sequence(state, &common_sequence)) {
        BTC_POLICY_TRACE_STAGE("btcpol:seq_bad");
        return false;
    }

    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    const uint32_t input_script_type = state->inputs[0].script_type;
    uint32_t account = 0;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        const bool supported = input_script_type == BITCOIN_P2PKH_SPENDADDRESS
                ? trezor_bitcoin_policy_input_is_p2pkh_verified(input, testnet)
            : input_script_type == BITCOIN_P2WPKH_SPENDWITNESS
                ? trezor_bitcoin_policy_input_is_supported_without_prev_tx_verification(input, testnet)
            : input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
                ? trezor_bitcoin_policy_input_is_p2sh_p2wpkh_verified(input, testnet)
                : false;
        if (!supported || input->script_type != input_script_type) {
            trezor_bitcoin_policy_trace_input_shape("btcpol:input_bad", i, input);
            return false;
        }
        if (input->address_n_len <= 2) {
            trezor_bitcoin_policy_trace_input_shape("btcpol:input_path", i, input);
            return false;
        }
        if (i == 0) {
            account = input->address_n[2];
        } else if (input->address_n[2] != account) {
            trezor_bitcoin_policy_trace_input_shape("btcpol:input_acct", i, input);
            return false;
        }
    }

    size_t external_outputs = 0;
    for (size_t i = 0; i < state->outputs_len; ++i) {
        const trezor_bitcoin_tx_output_t* const output = &state->outputs[i];
        if (!output->has_amount || output->has_multisig
            || !trezor_bitcoin_policy_output_script_is_external_address(output->script_type)) {
            trezor_bitcoin_policy_trace_output_shape("btcpol:out_shape", i, output);
            return false;
        }
        if (output->has_address) {
            ++external_outputs;
            if (output->address_n_len != 0) {
                trezor_bitcoin_policy_trace_output_shape("btcpol:out_addr_path", i, output);
                return false;
            }
        } else {
            if (!trezor_bitcoin_policy_output_script_matches_change(input_script_type, output->script_type)) {
                trezor_bitcoin_policy_trace_output_shape("btcpol:change_script", i, output);
                return false;
            }
            const bool change_ok = input_script_type == BITCOIN_P2WPKH_SPENDWITNESS
                    ? bitcoin_path_is_p2wpkh_internal(output->address_n, output->address_n_len, testnet, account)
                : input_script_type == BITCOIN_P2PKH_SPENDADDRESS
                    ? bitcoin_path_is_p2pkh_internal(output->address_n, output->address_n_len, testnet, account)
                : input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
                    ? bitcoin_path_is_p2sh_p2wpkh_internal(output->address_n, output->address_n_len, testnet, account)
                    : false;
            if (!change_ok) {
                trezor_bitcoin_policy_trace_change_path_mismatch(i, output, input_script_type, testnet, account);
                return false;
            }
        }
    }
    if (external_outputs > 1) {
        BTC_POLICY_TRACE_STAGE_NOTE(
            "btcpol:out_ext_many", "ext=%lu outs=%lu", (unsigned long)external_outputs,
            (unsigned long)state->outputs_len);
        return false;
    }
    if (external_outputs == 0 && state->total_output == 0) {
        BTC_POLICY_TRACE_STAGE_NOTE(
            "btcpol:out_ext_none", "ext=0 outs=%lu total=0", (unsigned long)state->outputs_len);
        return false;
    }
    if (state->total_input < state->total_output) {
        BTC_POLICY_TRACE_STAGE_NOTE("btcpol:insufficient", "total_in=%llu total_out=%llu",
            (unsigned long long)state->total_input,
            (unsigned long long)state->total_output);
        return false;
    }
    BTC_POLICY_TRACE_STAGE("btcpol:ok");
    return true;
}
#endif /* AMALGAMATED_BUILD */
