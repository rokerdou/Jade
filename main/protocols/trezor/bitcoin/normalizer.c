#ifndef AMALGAMATED_BUILD
#include "normalizer.h"

#include "policy.h"
#include "script_builder.h"

#include <string.h>
#include <wally_address.h>
#include <wally_crypto.h>

static bool trezor_bitcoin_normalizer_add_u64(uint64_t* const total, const uint64_t value)
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
        const bool valid_output = trezor_bitcoin_script_builder_output_script(
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
            if (!trezor_bitcoin_normalizer_add_u64(&request->amount, output->amount)) {
                wally_bzero(request, sizeof(*request));
                return false;
            }
        } else if (!trezor_bitcoin_normalizer_add_u64(&request->change, output->amount)) {
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

bool trezor_bitcoin_signing_to_multisig_confirm_request(
    const trezor_bitcoin_signing_state_t* const state, bitcoin_confirm_request_t* const request)
{
    if (!state || !request || state->inputs_len == 0
        || state->inputs[0].address_n_len > CHAIN_CONFIRM_MAX_PATH_LEN) {
        return false;
    }

    trezor_bitcoin_multisig_preview_t preview;
    wally_bzero(&preview, sizeof(preview));
    if (!trezor_bitcoin_policy_multisig_preview(state, &preview)
        || preview.first_external_output_index >= state->outputs_len) {
        wally_bzero(&preview, sizeof(preview));
        return false;
    }

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    const trezor_bitcoin_tx_output_t* const external_output = &state->outputs[preview.first_external_output_index];
    uint8_t validated_script[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t validated_script_len = 0;
    wally_bzero(validated_script, sizeof(validated_script));
    const bool ok = trezor_bitcoin_policy_signing_coin(state, &coin)
        && trezor_bitcoin_script_builder_output_script(
            external_output, coin, validated_script, sizeof(validated_script), &validated_script_len)
        && validated_script_len > 0 && strlen(external_output->address) < sizeof(request->to);
    wally_bzero(validated_script, sizeof(validated_script));
    if (!ok) {
        wally_bzero(&preview, sizeof(preview));
        return false;
    }

    wally_bzero(request, sizeof(*request));
    request->path_len = state->inputs[0].address_n_len;
    memcpy(request->path, state->inputs[0].address_n, request->path_len * sizeof(request->path[0]));
    memcpy(request->to, external_output->address, strlen(external_output->address) + 1U);
    request->amount = preview.external_amount;
    request->change = preview.change_amount;
    request->fee = state->fee;
    request->fee_rate_sats_per_vbyte = state->fee_rate_sats_per_vbyte;
    wally_bzero(&preview, sizeof(preview));
    return true;
}
#endif /* AMALGAMATED_BUILD */
