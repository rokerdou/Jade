#ifndef AMALGAMATED_BUILD
#include "tx.h"

#include "path.h"

#include <string.h>
#include <wally_crypto.h>

static bool bytes_are_zero(const uint8_t* const bytes, const size_t bytes_len)
{
    if (!bytes) {
        return bytes_len == 0;
    }
    for (size_t i = 0; i < bytes_len; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool value_valid(const uint8_t* const value, const size_t value_len)
{
    return value_len <= EVM_ABI_WORD_LEN && (value || value_len == 0);
}

static bool tx_type_valid(const ethereum_tx_preflight_request_t* const request)
{
    if (request->tx_type == ETHEREUM_TX_TYPE_LEGACY) {
        return request->chain_id != 0 && request->gas_limit != 0 && request->gas_price != 0;
    }
    if (request->tx_type == ETHEREUM_TX_TYPE_EIP2930) {
        return request->chain_id != 0 && request->gas_limit != 0 && request->gas_price != 0;
    }
    if (request->tx_type == ETHEREUM_TX_TYPE_EIP1559) {
        return request->chain_id != 0 && request->gas_limit != 0 && request->max_fee_per_gas != 0
            && request->max_priority_fee_per_gas <= request->max_fee_per_gas;
    }
    return false;
}

static bool fee_product_fits_u64(const uint64_t fee_per_gas, const uint64_t gas_limit)
{
    return fee_per_gas == 0 || gas_limit <= UINT64_MAX / fee_per_gas;
}

static bool token_definition_valid_for_result(const ethereum_tx_preflight_request_t* const request,
    const ethereum_tx_preflight_result_t* const result)
{
    if (!request->has_token_definition) {
        return true;
    }
    if (!result || (result->type != ETHEREUM_TX_SUMMARY_ERC20_TRANSFER
                       && result->type != ETHEREUM_TX_SUMMARY_ERC20_APPROVE)) {
        return false;
    }
    return request->token_definition.chain_id == request->chain_id
        && request->token_definition.decimals <= ETHEREUM_TOKEN_DECIMALS_MAX
        && request->token_definition.symbol[0] != '\0'
        && strnlen(request->token_definition.symbol, sizeof(request->token_definition.symbol))
            < sizeof(request->token_definition.symbol)
        && request->token_definition.name[0] != '\0'
        && strnlen(request->token_definition.name, sizeof(request->token_definition.name))
            < sizeof(request->token_definition.name)
        && memcmp(request->token_definition.address, result->token_contract, ETHEREUM_ADDRESS_LEN) == 0;
}

bool ethereum_tx_preflight(
    const ethereum_tx_preflight_request_t* const request, ethereum_tx_preflight_result_t* const result)
{
    if (!request || !result || !ethereum_path_is_supported(request->path, request->path_len) || !tx_type_valid(request)
        || !value_valid(request->value, request->value_len) || request->data_len > ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN
        || (!request->data && request->data_len) || !request->sender_address
        || request->sender_address_len != ETHEREUM_ADDRESS_LEN) {
        return false;
    }
    if (request->expected_sender_address || request->expected_sender_address_len) {
        if (!request->expected_sender_address || request->expected_sender_address_len != ETHEREUM_ADDRESS_LEN
            || memcmp(request->sender_address, request->expected_sender_address, ETHEREUM_ADDRESS_LEN) != 0) {
            return false;
        }
    }

    const uint64_t max_fee
        = request->tx_type == ETHEREUM_TX_TYPE_EIP1559 ? request->max_fee_per_gas : request->gas_price;
    if (!fee_product_fits_u64(max_fee, request->gas_limit)) {
        return false;
    }

    wally_bzero(result, sizeof(*result));
    memcpy(result->sender, request->sender_address, sizeof(result->sender));
    result->has_to = request->has_to;
    if (request->has_to) {
        memcpy(result->to, request->to, sizeof(result->to));
    }

    if (request->data_len == 0) {
        if (!request->has_to || request->has_token_definition) {
            return false;
        }
        result->type = ETHEREUM_TX_SUMMARY_NATIVE_TRANSFER;
        return true;
    }

    if (!request->has_to) {
        return false;
    }

    evm_abi_address_uint256_call_t call;
    if (evm_abi_parse_address_uint256_call(request->data, request->data_len, &call)) {
        if (!bytes_are_zero(request->value, request->value_len)) {
            wally_bzero(&call, sizeof(call));
            return false;
        }
        result->type = call.type == EVM_ABI_CALL_ERC20_TRANSFER ? ETHEREUM_TX_SUMMARY_ERC20_TRANSFER
                                                                : ETHEREUM_TX_SUMMARY_ERC20_APPROVE;
        memcpy(result->token_contract, request->to, sizeof(result->token_contract));
        memcpy(result->token_recipient, call.address, sizeof(result->token_recipient));
        memcpy(result->token_amount, call.amount, sizeof(result->token_amount));
        wally_bzero(&call, sizeof(call));
        return token_definition_valid_for_result(request, result);
    }

    if (request->has_token_definition || !request->allow_unknown_contract_call) {
        return false;
    }

    result->type = ETHEREUM_TX_SUMMARY_CONTRACT_CALL;
    return true;
}
#endif /* AMALGAMATED_BUILD */
