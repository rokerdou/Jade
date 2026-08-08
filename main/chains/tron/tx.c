#ifndef AMALGAMATED_BUILD
#include "tx.h"

#include "path.h"

#include <string.h>
#include <wally_crypto.h>

static bool tron_address_valid(const uint8_t* const address, const size_t address_len)
{
    return address && address_len == TRON_ADDRESS_LEN && address[0] == TRON_ADDRESS_PREFIX;
}

static bool owner_matches_signer(const tron_tx_preflight_request_t* const request)
{
    return tron_address_valid(request->signer_address, request->signer_address_len)
        && tron_address_valid(request->owner_address, request->owner_address_len)
        && memcmp(request->signer_address, request->owner_address, TRON_ADDRESS_LEN) == 0;
}

static bool common_fields_valid(const tron_tx_preflight_request_t* const request)
{
    return request && tron_path_is_supported(request->path, request->path_len) && owner_matches_signer(request)
        && request->fee_limit <= TRON_TX_MAX_FEE_LIMIT_SUN
        && (!request->memo || request->memo_len <= TRON_TX_MAX_MEMO_LEN) && (request->memo || request->memo_len == 0);
}

bool tron_tx_preflight(const tron_tx_preflight_request_t* const request, tron_tx_preflight_result_t* const result)
{
    if (!common_fields_valid(request) || !result) {
        return false;
    }

    wally_bzero(result, sizeof(*result));
    memcpy(result->owner, request->owner_address, sizeof(result->owner));

    if (request->contract_type == TRON_TX_CONTRACT_TRANSFER) {
        if (request->transfer_amount > TRON_TX_MAX_SIGNED_AMOUNT
            || !tron_address_valid(request->transfer_to, sizeof(request->transfer_to))) {
            return false;
        }
        result->type = TRON_TX_SUMMARY_TRX_TRANSFER;
        result->trx_amount = request->transfer_amount;
        memcpy(result->recipient, request->transfer_to, sizeof(result->recipient));
        return true;
    }

    if (request->contract_type != TRON_TX_CONTRACT_TRIGGER_SMART_CONTRACT
        || !tron_address_valid(request->contract_address, sizeof(request->contract_address)) || request->call_value != 0
        || (!request->contract_data && request->contract_data_len)) {
        return false;
    }

    evm_abi_address_uint256_call_t call;
    if (evm_abi_parse_address_uint256_call(request->contract_data, request->contract_data_len, &call)) {
        result->type
            = call.type == EVM_ABI_CALL_ERC20_TRANSFER ? TRON_TX_SUMMARY_TRC20_TRANSFER : TRON_TX_SUMMARY_TRC20_APPROVE;
        memcpy(result->contract_address, request->contract_address, sizeof(result->contract_address));
        result->recipient[0] = TRON_ADDRESS_PREFIX;
        memcpy(result->recipient + 1, call.address, sizeof(call.address));
        memcpy(result->token_amount, call.amount, sizeof(result->token_amount));
        wally_bzero(&call, sizeof(call));
        return true;
    }

    if (!request->allow_unknown_contract_call) {
        return false;
    }

    result->type = TRON_TX_SUMMARY_UNKNOWN_SMART_CONTRACT;
    memcpy(result->contract_address, request->contract_address, sizeof(result->contract_address));
    return true;
}
#endif /* AMALGAMATED_BUILD */
