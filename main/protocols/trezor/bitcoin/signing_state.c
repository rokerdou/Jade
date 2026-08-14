#ifndef AMALGAMATED_BUILD
#include "signing_state.h"

#include "messages.h"
#include "policy.h"
#include "prev_tx_verifier.h"
#include "requests.h"

#include "../../../chains/bitcoin/path.h"

#include <wally_crypto.h>

void trezor_bitcoin_signing_reset(trezor_bitcoin_signing_state_t* const state)
{
    if (!state) {
        return;
    }
    trezor_bitcoin_prev_tx_verifier_reset(&state->prev_tx_verifier);
    wally_bzero(state, sizeof(*state));
}

static bool trezor_bitcoin_signing_input_needs_prev_tx(const trezor_bitcoin_tx_input_t* const input)
{
    return input && (input->script_type == BITCOIN_P2PKH_SPENDADDRESS
                        || input->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS);
}

static bool trezor_bitcoin_signing_inputs_are_all_p2wpkh(const trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len != state->request.inputs_count) {
        return false;
    }
    for (size_t i = 0; i < state->inputs_len; ++i) {
        if (state->inputs[i].script_type != BITCOIN_P2WPKH_SPENDWITNESS) {
            return false;
        }
    }
    return true;
}

static bool trezor_bitcoin_signing_finish_current_tx(trezor_bitcoin_signing_state_t* const state)
{
    if (!trezor_bitcoin_policy_calculate_totals(state)) {
        return false;
    }
    if (trezor_bitcoin_signing_inputs_are_all_p2wpkh(state)
        && !trezor_bitcoin_policy_estimate_p2wpkh_fee_rate(state)) {
        return false;
    }
    state->phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
    return true;
}

static bool trezor_bitcoin_signing_start_next_prev_tx(trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len != state->request.inputs_count
        || state->outputs_len != state->request.outputs_count) {
        return false;
    }

    trezor_bitcoin_prev_tx_verifier_reset(&state->prev_tx_verifier);
    for (size_t i = state->prev_tx_input_index; i < state->inputs_len; ++i) {
        if (trezor_bitcoin_signing_input_needs_prev_tx(&state->inputs[i])) {
            state->prev_tx_input_index = i;
            state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_META;
            return true;
        }
    }

    return trezor_bitcoin_signing_finish_current_tx(state);
}

bool trezor_bitcoin_signing_init(
    trezor_bitcoin_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state) {
        return false;
    }

    trezor_bitcoin_signing_reset(state);
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

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META) {
        trezor_bitcoin_transaction_t tx_ack;
        if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
            return false;
        }
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
        trezor_bitcoin_transaction_t tx_ack;
        if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
            return false;
        }
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
        trezor_bitcoin_transaction_t tx_ack;
        if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
            return false;
        }
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 1 || state->outputs_len >= state->request.outputs_count) {
            return false;
        }
        state->outputs[state->outputs_len++] = tx_ack.outputs[0];
        if (state->outputs_len < state->request.outputs_count) {
            return true;
        }
        return trezor_bitcoin_signing_start_next_prev_tx(state);
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_META) {
        trezor_bitcoin_transaction_t tx_ack;
        if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
            return false;
        }
        if (state->prev_tx_input_index >= state->inputs_len) {
            return false;
        }
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[state->prev_tx_input_index];
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 0
            || !trezor_bitcoin_prev_tx_verifier_init(
                &state->prev_tx_verifier, &tx_ack, input->prev_hash, sizeof(input->prev_hash), input->prev_index)) {
            return false;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_INPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_INPUT) {
        trezor_bitcoin_prev_input_t prev_input;
        if (state->prev_tx_input_index >= state->inputs_len
            || !trezor_bitcoin_tx_ack_prev_input_decode(payload, payload_len, &prev_input)
            || !trezor_bitcoin_prev_tx_verifier_apply_input(&state->prev_tx_verifier, &prev_input)) {
            return false;
        }
        wally_bzero(&prev_input, sizeof(prev_input));
        if (state->prev_tx_verifier.inputs_seen < state->prev_tx_verifier.inputs_count) {
            return true;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_OUTPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_OUTPUT) {
        trezor_bitcoin_prev_output_t prev_output;
        uint8_t script_pubkey[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
        size_t script_pubkey_len = 0;
        uint64_t amount = 0;
        wally_bzero(&prev_output, sizeof(prev_output));
        wally_bzero(script_pubkey, sizeof(script_pubkey));
        if (state->prev_tx_input_index >= state->inputs_len
            || !trezor_bitcoin_tx_ack_prev_output_decode(payload, payload_len, &prev_output)
            || !trezor_bitcoin_prev_tx_verifier_apply_output(&state->prev_tx_verifier, &prev_output)) {
            wally_bzero(&prev_output, sizeof(prev_output));
            return false;
        }
        wally_bzero(&prev_output, sizeof(prev_output));
        if (state->prev_tx_verifier.outputs_seen < state->prev_tx_verifier.outputs_count) {
            return true;
        }
        if (!trezor_bitcoin_prev_tx_verifier_finish(
                &state->prev_tx_verifier, &amount, script_pubkey, sizeof(script_pubkey), &script_pubkey_len)
            || script_pubkey_len == 0) {
            wally_bzero(script_pubkey, sizeof(script_pubkey));
            return false;
        }
        trezor_bitcoin_tx_input_t* const input = &state->inputs[state->prev_tx_input_index];
        input->amount = amount;
        input->has_amount = true;
        ++state->prev_tx_input_index;
        wally_bzero(script_pubkey, sizeof(script_pubkey));
        return trezor_bitcoin_signing_start_next_prev_tx(state);
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
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_META) {
        if (state->prev_tx_input_index >= state->inputs_len
            || !state->inputs[state->prev_tx_input_index].has_prev_hash) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXMETA, false, 0,
            state->inputs[state->prev_tx_input_index].prev_hash, sizeof(state->inputs[state->prev_tx_input_index].prev_hash),
            output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_INPUT) {
        if (state->prev_tx_input_index >= state->inputs_len
            || state->prev_tx_verifier.inputs_seen >= state->prev_tx_verifier.inputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXORIGINPUT, true,
            (uint32_t)state->prev_tx_verifier.inputs_seen, state->inputs[state->prev_tx_input_index].prev_hash,
            sizeof(state->inputs[state->prev_tx_input_index].prev_hash), output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_PREV_OUTPUT) {
        if (state->prev_tx_input_index >= state->inputs_len
            || state->prev_tx_verifier.outputs_seen >= state->prev_tx_verifier.outputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode_with_tx_hash(TREZOR_BITCOIN_REQUEST_TXORIGOUTPUT, true,
            (uint32_t)state->prev_tx_verifier.outputs_seen, state->inputs[state->prev_tx_input_index].prev_hash,
            sizeof(state->inputs[state->prev_tx_input_index].prev_hash), output, output_len, written);
    }
    return false;
}

bool trezor_bitcoin_signing_ready(const trezor_bitcoin_signing_state_t* const state)
{
    return state && state->phase == TREZOR_BITCOIN_SIGNING_PHASE_READY;
}
#endif /* AMALGAMATED_BUILD */
