#ifndef AMALGAMATED_BUILD
#include "evm_abi.h"

#include <string.h>
#include <wally_crypto.h>

static const uint8_t ERC20_TRANSFER_SELECTOR[EVM_ABI_SELECTOR_LEN] = { 0xa9, 0x05, 0x9c, 0xbb };
static const uint8_t ERC20_APPROVE_SELECTOR[EVM_ABI_SELECTOR_LEN] = { 0x09, 0x5e, 0xa7, 0xb3 };

evm_abi_call_type_t evm_abi_classify_selector(const uint8_t* const selector, const size_t selector_len)
{
    if (!selector || selector_len != EVM_ABI_SELECTOR_LEN) {
        return EVM_ABI_CALL_UNSUPPORTED;
    }

    if (memcmp(selector, ERC20_TRANSFER_SELECTOR, sizeof(ERC20_TRANSFER_SELECTOR)) == 0) {
        return EVM_ABI_CALL_ERC20_TRANSFER;
    }
    if (memcmp(selector, ERC20_APPROVE_SELECTOR, sizeof(ERC20_APPROVE_SELECTOR)) == 0) {
        return EVM_ABI_CALL_ERC20_APPROVE;
    }

    return EVM_ABI_CALL_UNSUPPORTED;
}

bool evm_abi_parse_address_uint256_call(
    const uint8_t* const data, const size_t data_len, evm_abi_address_uint256_call_t* const output)
{
    if (!data || data_len != EVM_ABI_ADDRESS_UINT256_CALL_LEN || !output) {
        return false;
    }

    const evm_abi_call_type_t type = evm_abi_classify_selector(data, EVM_ABI_SELECTOR_LEN);
    if (type == EVM_ABI_CALL_UNSUPPORTED) {
        return false;
    }

    const uint8_t* const address_word = data + EVM_ABI_SELECTOR_LEN;
    for (size_t i = 0; i < EVM_ABI_ADDRESS_PAD_LEN; ++i) {
        if (address_word[i] != 0) {
            return false;
        }
    }

    wally_bzero(output, sizeof(*output));
    output->type = type;
    memcpy(output->address, address_word + EVM_ABI_ADDRESS_PAD_LEN, sizeof(output->address));
    memcpy(output->amount, data + EVM_ABI_SELECTOR_LEN + EVM_ABI_WORD_LEN, sizeof(output->amount));
    return true;
}
#endif /* AMALGAMATED_BUILD */
