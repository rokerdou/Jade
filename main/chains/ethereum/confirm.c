#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include "../../crypto/keccak256.h"

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
        return chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_AMOUNT, request->value, request->value_len);
    }

    if (result->type == ETHEREUM_TX_SUMMARY_ERC20_TRANSFER || result->type == ETHEREUM_TX_SUMMARY_ERC20_APPROVE) {
        return chain_confirm_summary_add_bytes(
                   summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT, result->token_contract, sizeof(result->token_contract))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT, result->token_recipient, sizeof(result->token_recipient))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT, result->token_amount, sizeof(result->token_amount));
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
