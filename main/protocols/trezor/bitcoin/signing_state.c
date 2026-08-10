#ifndef AMALGAMATED_BUILD
#include "signing_state.h"

#include "messages.h"
#include "policy.h"
#include "requests.h"

#include <wally_crypto.h>

bool trezor_bitcoin_signing_init(
    trezor_bitcoin_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state) {
        return false;
    }

    wally_bzero(state, sizeof(*state));
    if (!trezor_bitcoin_sign_tx_decode(payload, payload_len, &state->request)) {
        return false;
    }
    state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META;
    return true;
}

bool trezor_bitcoin_signing_apply_tx_ack(
    trezor_bitcoin_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state || state->phase == TREZOR_BITCOIN_SIGNING_PHASE_NONE
        || state->phase == TREZOR_BITCOIN_SIGNING_PHASE_READY) {
        return false;
    }

    trezor_bitcoin_transaction_t tx_ack;
    if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
        return false;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META) {
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 0 || !tx_ack.has_inputs_cnt || !tx_ack.has_outputs_cnt
            || tx_ack.inputs_cnt != state->request.inputs_count || tx_ack.outputs_cnt != state->request.outputs_count
            || (tx_ack.has_version && tx_ack.version != state->request.version)
            || (tx_ack.has_lock_time && tx_ack.lock_time != state->request.lock_time)) {
            return false;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT) {
        if (tx_ack.inputs_len != 1 || tx_ack.outputs_len != 0 || state->inputs_len >= state->request.inputs_count) {
            return false;
        }
        state->inputs[state->inputs_len++] = tx_ack.inputs[0];
        if (state->inputs_len < state->request.inputs_count) {
            return true;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT) {
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 1 || state->outputs_len >= state->request.outputs_count) {
            return false;
        }
        state->outputs[state->outputs_len++] = tx_ack.outputs[0];
        if (state->outputs_len < state->request.outputs_count) {
            return true;
        }
        if (!trezor_bitcoin_policy_calculate_totals(state)
            || !trezor_bitcoin_policy_estimate_p2wpkh_fee_rate(state)) {
            return false;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
        return true;
    }

    return false;
}

bool trezor_bitcoin_signing_encode_next_request(const trezor_bitcoin_signing_state_t* const state, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!state || !output || !written) {
        return false;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META) {
        return trezor_bitcoin_tx_request_encode(
            TREZOR_BITCOIN_REQUEST_TXMETA, false, 0, output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT) {
        if (state->inputs_len >= state->request.inputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXINPUT, true, (uint32_t)state->inputs_len,
            output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT) {
        if (state->outputs_len >= state->request.outputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXOUTPUT, true, (uint32_t)state->outputs_len,
            output, output_len, written);
    }
    return false;
}

bool trezor_bitcoin_signing_ready(const trezor_bitcoin_signing_state_t* const state)
{
    return state && state->phase == TREZOR_BITCOIN_SIGNING_PHASE_READY;
}
#endif /* AMALGAMATED_BUILD */
