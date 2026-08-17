#ifndef AMALGAMATED_BUILD
#include "normalizer.h"

#include "policy.h"
#include "script_builder.h"

#include <string.h>
#include <stdio.h>
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

static bool trezor_bitcoin_normalizer_copy_address(
    char* const dst, const size_t dst_len, const char* const src, const size_t src_max_len)
{
    if (!dst || dst_len == 0 || !src || src_max_len == 0) {
        return false;
    }
    const size_t src_len = strnlen(src, src_max_len);
    if (src_len == src_max_len || src_len >= dst_len) {
        return false;
    }
    memcpy(dst, src, src_len + 1U);
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
            if (external_outputs == 1
                && !trezor_bitcoin_normalizer_copy_address(
                    request->to, sizeof(request->to), output->address, sizeof(output->address))) {
                wally_bzero(request, sizeof(*request));
                return false;
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

static const char* trezor_bitcoin_multisig_policy_name(const script_variant_t variant)
{
    switch (variant) {
    case MULTI_P2SH:
        return "P2SH";
    case MULTI_P2WSH:
        return "P2WSH";
    case MULTI_P2WSH_P2SH:
        return "P2SH-P2WSH";
    default:
        return NULL;
    }
}

static bool trezor_bitcoin_multisig_policy_text(
    const trezor_bitcoin_multisig_summary_t* const multisig, char* const output, const size_t output_len)
{
    const char* const policy_name = multisig ? trezor_bitcoin_multisig_policy_name(multisig->variant) : NULL;
    if (!multisig || !output || output_len == 0 || !policy_name || multisig->threshold == 0
        || multisig->num_pubkeys == 0 || multisig->threshold > multisig->num_pubkeys) {
        return false;
    }
    const int ret = snprintf(output, output_len, "%u-of-%u %s", (unsigned int)multisig->threshold,
        (unsigned int)multisig->num_pubkeys, policy_name);
    return ret > 0 && (size_t)ret < output_len;
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
        && validated_script_len > 0;
    wally_bzero(validated_script, sizeof(validated_script));
    if (!ok) {
        wally_bzero(&preview, sizeof(preview));
        return false;
    }

    wally_bzero(request, sizeof(*request));
    request->path_len = state->inputs[0].address_n_len;
    memcpy(request->path, state->inputs[0].address_n, request->path_len * sizeof(request->path[0]));
    if (!trezor_bitcoin_multisig_policy_text(&state->inputs[0].multisig, request->policy, sizeof(request->policy))) {
        wally_bzero(request, sizeof(*request));
        wally_bzero(&preview, sizeof(preview));
        return false;
    }
    if (!trezor_bitcoin_normalizer_copy_address(
            request->to, sizeof(request->to), external_output->address, sizeof(external_output->address))) {
        wally_bzero(request, sizeof(*request));
        wally_bzero(&preview, sizeof(preview));
        return false;
    }
    request->amount = preview.external_amount;
    request->change = preview.change_amount;
    request->fee = state->fee;
    request->fee_rate_sats_per_vbyte = state->fee_rate_sats_per_vbyte;
    wally_bzero(&preview, sizeof(preview));
    return true;
}
#endif /* AMALGAMATED_BUILD */
