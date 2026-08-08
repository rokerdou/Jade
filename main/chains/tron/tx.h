#ifndef TRON_TX_H_
#define TRON_TX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../evm_abi.h"
#include "address.h"

#define TRON_TX_MAX_MEMO_LEN 256
#define TRON_TX_MAX_FEE_LIMIT_SUN 15000000000ULL
#define TRON_TX_MAX_SIGNED_AMOUNT 9223372036854775807ULL

typedef enum {
    TRON_TX_CONTRACT_TRANSFER = 0,
    TRON_TX_CONTRACT_TRIGGER_SMART_CONTRACT,
} tron_tx_contract_type_t;

typedef enum {
    TRON_TX_SUMMARY_UNSUPPORTED = 0,
    TRON_TX_SUMMARY_TRX_TRANSFER,
    TRON_TX_SUMMARY_TRC20_TRANSFER,
    TRON_TX_SUMMARY_TRC20_APPROVE,
    TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT,
} tron_tx_summary_type_t;

typedef struct {
    const uint32_t* path;
    size_t path_len;
    const uint8_t* signer_address;
    size_t signer_address_len;
    const uint8_t* owner_address;
    size_t owner_address_len;
    tron_tx_contract_type_t contract_type;
    uint64_t fee_limit;
    const uint8_t* memo;
    size_t memo_len;
    uint8_t transfer_to[TRON_ADDRESS_LEN];
    uint64_t transfer_amount;
    uint8_t contract_address[TRON_ADDRESS_LEN];
    const uint8_t* contract_data;
    size_t contract_data_len;
    uint64_t call_value;
    bool allow_unknown_contract_call;
} tron_tx_preflight_request_t;

typedef struct {
    tron_tx_summary_type_t type;
    uint8_t owner[TRON_ADDRESS_LEN];
    uint8_t recipient[TRON_ADDRESS_LEN];
    uint8_t contract_address[TRON_ADDRESS_LEN];
    uint64_t trx_amount;
    uint8_t token_amount[EVM_ABI_WORD_LEN];
} tron_tx_preflight_result_t;

bool tron_tx_preflight(const tron_tx_preflight_request_t* request, tron_tx_preflight_result_t* result);

#endif /* TRON_TX_H_ */
