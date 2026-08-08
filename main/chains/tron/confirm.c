#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include "../../crypto/keccak256.h"

static chain_confirm_operation_t tron_confirm_operation_from_result(const tron_tx_preflight_result_t* const result)
{
    if (result->type == TRON_TX_SUMMARY_TRC20_TRANSFER) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER;
    }
    if (result->type == TRON_TX_SUMMARY_TRC20_APPROVE) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE;
    }
    if (result->type == TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT) {
        return CHAIN_CONFIRM_OPERATION_CONTRACT_CALL;
    }
    return CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER;
}

bool tron_confirm_summary_from_preflight(const tron_tx_preflight_request_t* const request,
    const tron_tx_preflight_result_t* const result, chain_confirm_summary_t* const summary)
{
    if (!request || !result || !summary || result->type == TRON_TX_SUMMARY_UNSUPPORTED) {
        return false;
    }

    uint32_t flags = CHAIN_CONFIRM_FLAG_USER_CONFIRM;
    if (result->type == TRON_TX_SUMMARY_TRC20_APPROVE) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_APPROVAL;
    } else if (result->type == TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT;
    }

    chain_confirm_summary_init(summary, CHAIN_CONFIRM_CHAIN_TRON, tron_confirm_operation_from_result(result), flags);

    if (!chain_confirm_summary_add_path(summary, CHAIN_CONFIRM_FIELD_PATH, request->path, request->path_len)
        || !chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_OWNER, result->owner, sizeof(result->owner))
        || !chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_FEE_LIMIT, request->fee_limit)) {
        return false;
    }

    if (result->type == TRON_TX_SUMMARY_TRX_TRANSFER) {
        return chain_confirm_summary_add_bytes(
                   summary, CHAIN_CONFIRM_FIELD_TO, result->recipient, sizeof(result->recipient))
            && chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_AMOUNT, result->trx_amount);
    }

    if (result->type == TRON_TX_SUMMARY_TRC20_TRANSFER || result->type == TRON_TX_SUMMARY_TRC20_APPROVE) {
        return chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT, result->contract_address,
                   sizeof(result->contract_address))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT, result->recipient, sizeof(result->recipient))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT, result->token_amount, sizeof(result->token_amount));
    }

    if (result->type == TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT) {
        uint8_t calldata_hash[KECCAK256_LEN];
        if (!keccak256(request->contract_data, request->contract_data_len, calldata_hash, sizeof(calldata_hash))) {
            return false;
        }
        return chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT, result->contract_address,
                   sizeof(result->contract_address))
            && chain_confirm_summary_add_bytes(
                summary, CHAIN_CONFIRM_FIELD_CALLDATA_HASH, calldata_hash, sizeof(calldata_hash));
    }

    return false;
}
#endif /* AMALGAMATED_BUILD */
