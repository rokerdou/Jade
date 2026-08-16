#ifndef TREZOR_ETHEREUM_SAFE_NORMALIZER_H_
#define TREZOR_ETHEREUM_SAFE_NORMALIZER_H_

#include "../../../chains/ethereum/safe_tx.h"
#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    ethereum_safe_tx_t tx;
    uint8_t data[ETHEREUM_SAFE_TX_MAX_DATA_LEN];
} trezor_ethereum_safe_tx_ack_t;

bool trezor_ethereum_safe_tx_ack_decode(
    const uint8_t* payload, size_t payload_len, trezor_ethereum_safe_tx_ack_t* output);
bool trezor_ethereum_safe_tx_request_encode(uint8_t* output, size_t output_len, size_t* written);
bool trezor_ethereum_safe_typed_hash_bind(const trezor_ethereum_sign_typed_hash_t* typed_hash,
    const ethereum_safe_tx_t* safe_tx, uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN],
    ethereum_safe_tx_summary_t* summary);

#endif /* TREZOR_ETHEREUM_SAFE_NORMALIZER_H_ */
