#ifndef TREZOR_BITCOIN_NORMALIZER_H_
#define TREZOR_BITCOIN_NORMALIZER_H_

#include "protocol.h"

bool trezor_bitcoin_signing_to_confirm_request(
    const trezor_bitcoin_signing_state_t* state, bitcoin_confirm_request_t* request);
bool trezor_bitcoin_signing_to_multisig_confirm_request(
    const trezor_bitcoin_signing_state_t* state, bitcoin_confirm_request_t* request);
bool trezor_bitcoin_confirm_request_matches_state(
    const trezor_bitcoin_signing_state_t* state, const bitcoin_confirm_request_t* request);
bool trezor_bitcoin_multisig_confirm_request_matches_state(
    const trezor_bitcoin_signing_state_t* state, const bitcoin_confirm_request_t* request);

#endif /* TREZOR_BITCOIN_NORMALIZER_H_ */
