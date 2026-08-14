#ifndef TREZOR_BITCOIN_MESSAGES_H_
#define TREZOR_BITCOIN_MESSAGES_H_

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool trezor_bitcoin_get_address_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_get_address_t* output);
bool trezor_bitcoin_sign_tx_decode(const uint8_t* payload, size_t payload_len, trezor_bitcoin_sign_tx_t* output);
bool trezor_bitcoin_tx_ack_decode(const uint8_t* payload, size_t payload_len, trezor_bitcoin_transaction_t* output);
bool trezor_bitcoin_tx_ack_prev_input_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_input_t* output);
bool trezor_bitcoin_tx_ack_prev_output_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_output_t* output);
bool trezor_bitcoin_prev_input_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_input_t* output);
bool trezor_bitcoin_prev_output_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_output_t* output);
bool trezor_bitcoin_address_encode(const char* address, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_BITCOIN_MESSAGES_H_ */
