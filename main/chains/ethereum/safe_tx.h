#ifndef ETHEREUM_SAFE_TX_H_
#define ETHEREUM_SAFE_TX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../crypto/keccak256.h"
#include "../confirm_summary.h"
#include "../evm_abi.h"
#include "address.h"
#include "digest.h"
#include "tx.h"

#define ETHEREUM_SAFE_TX_MAX_DATA_LEN ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN

typedef enum {
    ETHEREUM_SAFE_TX_OPERATION_CALL = 0,
    ETHEREUM_SAFE_TX_OPERATION_DELEGATE_CALL = 1,
} ethereum_safe_tx_operation_t;

typedef enum {
    ETHEREUM_SAFE_TX_SUMMARY_UNSUPPORTED = 0,
    ETHEREUM_SAFE_TX_SUMMARY_NATIVE_TRANSFER,
    ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER,
    ETHEREUM_SAFE_TX_SUMMARY_ERC20_APPROVE,
    ETHEREUM_SAFE_TX_SUMMARY_CONTRACT_CALL,
} ethereum_safe_tx_summary_type_t;

typedef struct {
    uint64_t chain_id;
    uint8_t verifying_contract[ETHEREUM_ADDRESS_LEN];
    uint8_t to[ETHEREUM_ADDRESS_LEN];
    uint8_t value[EVM_ABI_WORD_LEN];
    const uint8_t* data;
    size_t data_len;
    ethereum_safe_tx_operation_t operation;
    uint8_t safe_tx_gas[EVM_ABI_WORD_LEN];
    uint8_t base_gas[EVM_ABI_WORD_LEN];
    uint8_t gas_price[EVM_ABI_WORD_LEN];
    uint8_t gas_token[ETHEREUM_ADDRESS_LEN];
    uint8_t refund_receiver[ETHEREUM_ADDRESS_LEN];
    uint8_t nonce[EVM_ABI_WORD_LEN];
} ethereum_safe_tx_t;

typedef struct {
    ethereum_safe_tx_summary_type_t type;
    uint8_t safe_address[ETHEREUM_ADDRESS_LEN];
    uint8_t to[ETHEREUM_ADDRESS_LEN];
    uint8_t token_contract[ETHEREUM_ADDRESS_LEN];
    uint8_t token_recipient[ETHEREUM_ADDRESS_LEN];
    uint8_t token_amount[EVM_ABI_WORD_LEN];
    uint8_t calldata_hash[KECCAK256_LEN];
} ethereum_safe_tx_summary_t;

bool ethereum_safe_tx_validate(const ethereum_safe_tx_t* tx);
bool ethereum_safe_tx_domain_separator_hash(
    uint64_t chain_id, const uint8_t verifying_contract[ETHEREUM_ADDRESS_LEN], uint8_t output[KECCAK256_LEN]);
bool ethereum_safe_tx_message_hash(const ethereum_safe_tx_t* tx, uint8_t output[KECCAK256_LEN]);
bool ethereum_safe_tx_signing_hash(const ethereum_safe_tx_t* tx, uint8_t output[ETHEREUM_TX_SIGNING_HASH_LEN]);
bool ethereum_safe_tx_preflight(const ethereum_safe_tx_t* tx, ethereum_safe_tx_summary_t* summary);
bool ethereum_safe_tx_confirm_summary_from_preflight(const uint32_t* path, size_t path_len,
    const ethereum_safe_tx_t* tx, const ethereum_safe_tx_summary_t* result,
    const uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN], chain_confirm_summary_t* summary);

#endif /* ETHEREUM_SAFE_TX_H_ */
