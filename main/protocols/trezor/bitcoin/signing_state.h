#ifndef TREZOR_BITCOIN_SIGNING_STATE_H_
#define TREZOR_BITCOIN_SIGNING_STATE_H_

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void trezor_bitcoin_signing_reset(trezor_bitcoin_signing_state_t* state);
bool trezor_bitcoin_signing_init(
    trezor_bitcoin_signing_state_t* state, const uint8_t* payload, size_t payload_len);
bool trezor_bitcoin_signing_apply_tx_ack(
    trezor_bitcoin_signing_state_t* state, const uint8_t* payload, size_t payload_len);
bool trezor_bitcoin_signing_encode_next_request(
    const trezor_bitcoin_signing_state_t* state, uint8_t* output, size_t output_len, size_t* written);
bool trezor_bitcoin_signing_ready(const trezor_bitcoin_signing_state_t* state);

#endif /* TREZOR_BITCOIN_SIGNING_STATE_H_ */
