#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include "../../crypto/keccak256.h"

#include <stdio.h>
#include <string.h>
#include <wally_crypto.h>

#define ETHEREUM_UINT256_DECIMAL_MAX_LEN 78
#define ETHEREUM_AMOUNT_TEXT_MAX_LEN (ETHEREUM_UINT256_DECIMAL_MAX_LEN + 5)

static bool fee_product(const ethereum_tx_preflight_request_t* const request, uint64_t* const output)
{
    const uint64_t fee_per_gas
        = request->tx_type == ETHEREUM_TX_TYPE_EIP1559 ? request->max_fee_per_gas : request->gas_price;
    if (!output || (fee_per_gas != 0 && request->gas_limit > UINT64_MAX / fee_per_gas)) {
        return false;
    }
    *output = fee_per_gas * request->gas_limit;
    return true;
}

static chain_confirm_operation_t ethereum_confirm_operation_from_result(
    const ethereum_tx_preflight_result_t* const result)
{
    if (result->type == ETHEREUM_TX_SUMMARY_ERC20_TRANSFER) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER;
    }
    if (result->type == ETHEREUM_TX_SUMMARY_ERC20_APPROVE) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE;
    }
    if (result->type == ETHEREUM_TX_SUMMARY_CONTRACT_CALL) {
        return CHAIN_CONFIRM_OPERATION_CONTRACT_CALL;
    }
    return CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER;
}

static bool ethereum_format_uint_be_decimal(
    const uint8_t* const value, const size_t value_len, char* const output, const size_t output_len)
{
    if ((!value && value_len) || value_len > EVM_ABI_WORD_LEN || !output || output_len == 0) {
        return false;
    }

    uint8_t work[EVM_ABI_WORD_LEN];
    wally_bzero(work, sizeof(work));
    if (value_len) {
        memcpy(work + sizeof(work) - value_len, value, value_len);
    }

    char digits[ETHEREUM_UINT256_DECIMAL_MAX_LEN + 1];
    size_t digits_len = 0;
    while (true) {
        bool any = false;
        uint16_t rem = 0;
        for (size_t i = 0; i < sizeof(work); ++i) {
            const uint16_t current = (uint16_t)((rem << 8) | work[i]);
            work[i] = (uint8_t)(current / 10U);
            rem = current % 10U;
            any = any || work[i] != 0;
        }
        if (digits_len >= ETHEREUM_UINT256_DECIMAL_MAX_LEN) {
            wally_bzero(work, sizeof(work));
            return false;
        }
        digits[digits_len++] = (char)('0' + rem);
        if (!any) {
            break;
        }
    }

    if (digits_len + 1 > output_len) {
        wally_bzero(work, sizeof(work));
        return false;
    }
    for (size_t i = 0; i < digits_len; ++i) {
        output[i] = digits[digits_len - 1 - i];
    }
    output[digits_len] = '\0';
    wally_bzero(work, sizeof(work));
    return true;
}

static bool ethereum_format_wei_amount(
    const uint8_t* const value, const size_t value_len, char* const output, const size_t output_len)
{
    char decimal[ETHEREUM_UINT256_DECIMAL_MAX_LEN + 1];
    if (!ethereum_format_uint_be_decimal(value, value_len, decimal, sizeof(decimal))) {
        return false;
    }

    const int ret = snprintf(output, output_len, "%s wei", decimal);
    return ret > 0 && (size_t)ret < output_len;
}

bool ethereum_confirm_summary_from_preflight(const ethereum_tx_preflight_request_t* const request,
    const ethereum_tx_preflight_result_t* const result, chain_confirm_summary_t* const summary)
{
    if (!request || !result || !summary || result->type == ETHEREUM_TX_SUMMARY_UNSUPPORTED) {
        return false;
    }

    uint64_t max_fee = 0;
    if (!fee_product(request, &max_fee)) {
        return false;
    }

    uint32_t flags = CHAIN_CONFIRM_FLAG_USER_CONFIRM;
    if (result->type == ETHEREUM_TX_SUMMARY_ERC20_APPROVE) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_APPROVAL;
    } else if (result->type == ETHEREUM_TX_SUMMARY_CONTRACT_CALL) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT;
    }

    chain_confirm_summary_init(
        summary, CHAIN_CONFIRM_CHAIN_ETHEREUM, ethereum_confirm_operation_from_result(result), flags);

    if (!chain_confirm_summary_add_path(summary, CHAIN_CONFIRM_FIELD_PATH, request->path, request->path_len)
        || !chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_CHAIN_ID, request->chain_id)
        || !chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_NONCE, request->nonce)
        || !chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_FROM, result->sender, sizeof(result->sender))
        || !chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_MAX_FEE, max_fee)) {
        return false;
    }

    if (result->has_to
        && !chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TO, result->to, sizeof(result->to))) {
        return false;
    }

    if (result->type == ETHEREUM_TX_SUMMARY_NATIVE_TRANSFER) {
        char amount[ETHEREUM_AMOUNT_TEXT_MAX_LEN];
        if (!ethereum_format_wei_amount(request->value, request->value_len, amount, sizeof(amount))) {
            return false;
        }
        return chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_AMOUNT, amount);
    }

    if (result->type == ETHEREUM_TX_SUMMARY_ERC20_TRANSFER || result->type == ETHEREUM_TX_SUMMARY_ERC20_APPROVE) {
        bool ok = chain_confirm_summary_add_bytes(
                      summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT, result->token_contract, sizeof(result->token_contract))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT, result->token_recipient, sizeof(result->token_recipient))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT, result->token_amount, sizeof(result->token_amount));
        if (ok && request->has_token_definition) {
            ok = chain_confirm_summary_add_text(
                     summary, CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL, request->token_definition.symbol)
                && chain_confirm_summary_add_u64(
                    summary, CHAIN_CONFIRM_FIELD_TOKEN_DECIMALS, request->token_definition.decimals)
                && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TOKEN_NAME, request->token_definition.name);
        }
        return ok;
    }

    if (result->type == ETHEREUM_TX_SUMMARY_CONTRACT_CALL) {
        uint8_t calldata_hash[KECCAK256_LEN];
        if (!keccak256(request->data, request->data_len, calldata_hash, sizeof(calldata_hash))) {
            return false;
        }
        return chain_confirm_summary_add_bytes(
            summary, CHAIN_CONFIRM_FIELD_CALLDATA_HASH, calldata_hash, sizeof(calldata_hash));
    }

    return false;
}
#endif /* AMALGAMATED_BUILD */
