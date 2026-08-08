#ifndef ETHEREUM_TX_REQUEST_H_
#define ETHEREUM_TX_REQUEST_H_

#include "tx.h"

#include "../../wallet_core/wallet_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t path[WALLET_CORE_MAX_PATH_LEN];
    uint8_t value[EVM_ABI_WORD_LEN];
    uint8_t data[ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN];
    ethereum_tx_preflight_request_t request;
} ethereum_tx_owned_request_t;

bool ethereum_tx_owned_request_init(ethereum_tx_owned_request_t* owned, const uint32_t* path, size_t path_len,
    ethereum_tx_type_t tx_type, uint64_t chain_id, uint64_t nonce, uint64_t gas_limit, uint64_t gas_price,
    uint64_t max_priority_fee_per_gas, uint64_t max_fee_per_gas, const uint8_t* to, size_t to_len, const uint8_t* value,
    size_t value_len, const uint8_t* data, size_t data_len, bool allow_unknown_contract_call);

#endif /* ETHEREUM_TX_REQUEST_H_ */
