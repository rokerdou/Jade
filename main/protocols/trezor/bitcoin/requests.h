#ifndef TREZOR_BITCOIN_REQUESTS_H_
#define TREZOR_BITCOIN_REQUESTS_H_

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool trezor_bitcoin_tx_request_encode(trezor_bitcoin_request_type_t request_type, bool has_request_index,
    uint32_t request_index, uint8_t* output, size_t output_len, size_t* written);
bool trezor_bitcoin_tx_request_encode_with_tx_hash(trezor_bitcoin_request_type_t request_type,
    bool has_request_index, uint32_t request_index, const uint8_t* tx_hash, size_t tx_hash_len,
    uint8_t* output, size_t output_len, size_t* written);
bool trezor_bitcoin_tx_request_encode_signed(const trezor_bitcoin_signing_state_t* state,
    const uint8_t* signature, size_t signature_len, const uint8_t* serialized_tx, size_t serialized_tx_len,
    uint8_t* output, size_t output_len, size_t* written);
bool trezor_bitcoin_signed_tx_encode_next(
    trezor_bitcoin_signed_tx_t* signed_tx, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_BITCOIN_REQUESTS_H_ */
