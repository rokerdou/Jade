#ifndef TREZOR_ETHEREUM_DEFINITIONS_H_
#define TREZOR_ETHEREUM_DEFINITIONS_H_

#include "../../chains/ethereum/tx.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool has_network;
    uint64_t network_chain_id;
    bool has_token;
    ethereum_token_metadata_t token;
} trezor_ethereum_definitions_t;

bool trezor_ethereum_definitions_decode(
    const uint8_t* payload, size_t payload_len, trezor_ethereum_definitions_t* output);

#endif /* TREZOR_ETHEREUM_DEFINITIONS_H_ */
