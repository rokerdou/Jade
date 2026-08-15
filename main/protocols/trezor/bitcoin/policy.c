#ifndef AMALGAMATED_BUILD
#include "policy.h"

#include "signing_state.h"
#include "../../../chains/bitcoin/path.h"

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
        const uint64_t input_vbytes = state->inputs[i].script_type == BITCOIN_P2PKH_SPENDADDRESS
            ? TREZOR_BITCOIN_P2PKH_INPUT_VBYTES
            : state->inputs[i].script_type == BITCOIN_P2WPKH_SPENDWITNESS
            ? TREZOR_BITCOIN_P2WPKH_INPUT_VBYTES
            : state->inputs[i].script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
            ? TREZOR_BITCOIN_P2SH_P2WPKH_INPUT_VBYTES
            : 0;
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
        if (!output->has_amount || output->has_multisig || output->script_type != BITCOIN_PAYTOADDRESS) {
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

bool trezor_bitcoin_policy_is_basic(const trezor_bitcoin_signing_state_t* const state)
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
        if (!output->has_amount || output->has_multisig || output->script_type != BITCOIN_PAYTOADDRESS) {
            return false;
        }
        if (output->has_address) {
            ++external_outputs;
            if (output->address_n_len != 0) {
                return false;
            }
        } else {
            const bool change_ok = input_script_type == BITCOIN_P2WPKH_SPENDWITNESS
                    ? bitcoin_path_is_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                : input_script_type == BITCOIN_P2PKH_SPENDADDRESS
                    ? bitcoin_path_is_p2pkh_change(output->address_n, output->address_n_len, testnet, account)
                : input_script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS
                    ? bitcoin_path_is_p2sh_p2wpkh_change(output->address_n, output->address_n_len, testnet, account)
                    : false;
            if (!change_ok) {
                return false;
            }
        }
    }
    return external_outputs == 1 && state->total_input >= state->total_output;
}
#endif /* AMALGAMATED_BUILD */
