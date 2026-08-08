#ifndef EVM_ABI_H_
#define EVM_ABI_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EVM_ABI_SELECTOR_LEN 4
#define EVM_ABI_WORD_LEN 32
#define EVM_ABI_ADDRESS_LEN 20
#define EVM_ABI_ADDRESS_PAD_LEN (EVM_ABI_WORD_LEN - EVM_ABI_ADDRESS_LEN)
#define EVM_ABI_ADDRESS_UINT256_CALL_LEN (EVM_ABI_SELECTOR_LEN + (2 * EVM_ABI_WORD_LEN))

typedef enum {
    EVM_ABI_CALL_UNSUPPORTED = 0,
    EVM_ABI_CALL_ERC20_TRANSFER,
    EVM_ABI_CALL_ERC20_APPROVE,
} evm_abi_call_type_t;

typedef struct {
    evm_abi_call_type_t type;
    uint8_t address[EVM_ABI_ADDRESS_LEN];
    uint8_t amount[EVM_ABI_WORD_LEN];
} evm_abi_address_uint256_call_t;

evm_abi_call_type_t evm_abi_classify_selector(const uint8_t* selector, size_t selector_len);
bool evm_abi_parse_address_uint256_call(const uint8_t* data, size_t data_len, evm_abi_address_uint256_call_t* output);

#endif /* EVM_ABI_H_ */
