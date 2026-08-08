#ifndef ETHEREUM_TX_H_
#define ETHEREUM_TX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../evm_abi.h"
#include "address.h"

#define ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN 6144

typedef enum {
    ETHEREUM_TX_TYPE_LEGACY = 0,
    ETHEREUM_TX_TYPE_EIP2930 = 1,
    ETHEREUM_TX_TYPE_EIP1559 = 2,
} ethereum_tx_type_t;

typedef enum {
    ETHEREUM_TX_SUMMARY_UNSUPPORTED = 0,
    ETHEREUM_TX_SUMMARY_NATIVE_TRANSFER,
    ETHEREUM_TX_SUMMARY_ERC20_TRANSFER,
    ETHEREUM_TX_SUMMARY_ERC20_APPROVE,
    ETHEREUM_TX_SUMMARY_CONTRACT_CALL,
} ethereum_tx_summary_type_t;

typedef struct {
    const uint32_t* path;
    size_t path_len;
    ethereum_tx_type_t tx_type;
    uint64_t chain_id;
    uint64_t nonce;
    uint64_t gas_limit;
    uint64_t gas_price;
    uint64_t max_priority_fee_per_gas;
    uint64_t max_fee_per_gas;
    bool has_to;
    uint8_t to[ETHEREUM_ADDRESS_LEN];
    const uint8_t* value;
    size_t value_len;
    const uint8_t* data;
    size_t data_len;
    const uint8_t* sender_address;
    size_t sender_address_len;
    const uint8_t* expected_sender_address;
    size_t expected_sender_address_len;
    bool allow_unknown_contract_call;
} ethereum_tx_preflight_request_t;

typedef struct {
    ethereum_tx_summary_type_t type;
    uint8_t sender[ETHEREUM_ADDRESS_LEN];
    uint8_t to[ETHEREUM_ADDRESS_LEN];
    bool has_to;
    uint8_t token_contract[ETHEREUM_ADDRESS_LEN];
    uint8_t token_recipient[ETHEREUM_ADDRESS_LEN];
    uint8_t token_amount[EVM_ABI_WORD_LEN];
} ethereum_tx_preflight_result_t;

bool ethereum_tx_preflight(const ethereum_tx_preflight_request_t* request, ethereum_tx_preflight_result_t* result);

#endif /* ETHEREUM_TX_H_ */
