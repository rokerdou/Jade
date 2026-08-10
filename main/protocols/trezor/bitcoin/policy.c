#ifndef AMALGAMATED_BUILD
#include "policy.h"

#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_crypto.h>

#define TREZOR_BITCOIN_P2WPKH_TX_OVERHEAD_VBYTES 11U
#define TREZOR_BITCOIN_P2WPKH_INPUT_VBYTES 68U
#define TREZOR_BITCOIN_P2WPKH_OUTPUT_VBYTES 31U
#define TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE 1000U

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

bool trezor_bitcoin_policy_signing_coin(
    const trezor_bitcoin_signing_state_t* const state, trezor_bitcoin_coin_t* const coin)
{
    return state && state->request.has_coin_name && trezor_bitcoin_coin_from_name(state->request.coin_name, coin);
}

static bool trezor_bitcoin_policy_input_is_supported_without_prev_tx_verification(
    const trezor_bitcoin_tx_input_t* const input, const bool testnet)
{
    return input && input->script_type == BITCOIN_P2WPKH_SPENDWITNESS && input->has_prev_hash
        && input->has_prev_index && input->has_amount
        && bitcoin_path_is_p2wpkh_signing(input->address_n, input->address_n_len, testnet);
}

bool trezor_bitcoin_policy_is_p2wpkh_basic(const trezor_bitcoin_signing_state_t* const state)
{
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    if (!state || !trezor_bitcoin_signing_ready(state) || state->inputs_len == 0 || state->outputs_len == 0
        || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count
        || !state->request.serialize || state->request.lock_time != 0
        || !trezor_bitcoin_policy_signing_coin(state, &coin)
        || state->fee_rate_sats_per_vbyte > TREZOR_BITCOIN_MAX_FEE_RATE_SATS_PER_VBYTE) {
        return false;
    }

    const bool testnet = trezor_bitcoin_coin_is_testnet(coin);
    uint32_t account = 0;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        if (!trezor_bitcoin_policy_input_is_supported_without_prev_tx_verification(input, testnet)) {
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
        if (!output->has_amount || output->script_type != 0) {
            return false;
        }
        if (output->has_address) {
            ++external_outputs;
            if (output->address_n_len != 0) {
                return false;
            }
        } else if (!bitcoin_path_is_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)) {
            return false;
        }
    }
    return external_outputs == 1 && state->total_input >= state->total_output;
}
#endif /* AMALGAMATED_BUILD */
