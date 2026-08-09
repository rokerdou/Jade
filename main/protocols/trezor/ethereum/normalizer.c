#ifndef AMALGAMATED_BUILD
#include "normalizer.h"

#include <string.h>
#include <wally_crypto.h>

bool trezor_ethereum_signing_state_to_request(
    const trezor_ethereum_signing_state_t* const state, ethereum_tx_preflight_request_t* const request)
{
    if (!trezor_ethereum_signing_state_ready(state) || !request) {
        return false;
    }
    if (state->definitions.has_network && state->definitions.network_chain_id != state->chain_id) {
        return false;
    }
    if (state->definitions.has_token && state->definitions.token.chain_id != state->chain_id) {
        return false;
    }

    wally_bzero(request, sizeof(*request));
    request->path = state->address_n;
    request->path_len = state->address_n_len;
    request->tx_type = state->tx_type;
    request->chain_id = state->chain_id;
    request->nonce = state->nonce;
    request->gas_limit = state->gas_limit;
    request->gas_price = state->gas_price;
    request->max_priority_fee_per_gas = state->max_priority_fee_per_gas;
    request->max_fee_per_gas = state->max_fee_per_gas;
    request->has_to = state->has_to;
    memcpy(request->to, state->to, sizeof(request->to));
    request->value = state->value_len ? state->value : NULL;
    request->value_len = state->value_len;
    request->data = state->data_len ? state->data : NULL;
    request->data_len = state->data_len;
    request->allow_unknown_contract_call = false;
    request->has_token_definition = state->definitions.has_token;
    if (state->definitions.has_token) {
        memcpy(&request->token_definition, &state->definitions.token, sizeof(request->token_definition));
    }
    return true;
}
#endif /* AMALGAMATED_BUILD */
