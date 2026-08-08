#ifndef AMALGAMATED_BUILD
#include "tx_request.h"

#include "path.h"

#include <string.h>
#include <wally_crypto.h>

static bool ethereum_tx_owned_type_supported(const ethereum_tx_type_t tx_type)
{
    return tx_type == ETHEREUM_TX_TYPE_LEGACY || tx_type == ETHEREUM_TX_TYPE_EIP1559;
}

static bool ethereum_tx_owned_scalar_valid(const uint8_t* const bytes, const size_t len)
{
    return (bytes || len == 0) && len <= EVM_ABI_WORD_LEN && (len == 0 || bytes[0] != 0);
}

bool ethereum_tx_owned_request_init(ethereum_tx_owned_request_t* const owned, const uint32_t* const path,
    const size_t path_len, const ethereum_tx_type_t tx_type, const uint64_t chain_id, const uint64_t nonce,
    const uint64_t gas_limit, const uint64_t gas_price, const uint64_t max_priority_fee_per_gas,
    const uint64_t max_fee_per_gas, const uint8_t* const to, const size_t to_len, const uint8_t* const value,
    const size_t value_len, const uint8_t* const data, const size_t data_len, const bool allow_unknown_contract_call)
{
    if (!owned || !ethereum_path_is_supported(path, path_len) || path_len > WALLET_CORE_MAX_PATH_LEN
        || !ethereum_tx_owned_type_supported(tx_type) || !to || to_len != ETHEREUM_ADDRESS_LEN
        || !ethereum_tx_owned_scalar_valid(value, value_len) || (!data && data_len)
        || data_len > ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN) {
        return false;
    }

    wally_bzero(owned, sizeof(*owned));
    memcpy(owned->path, path, path_len * sizeof(path[0]));
    if (value_len) {
        memcpy(owned->value, value, value_len);
    }
    if (data_len) {
        memcpy(owned->data, data, data_len);
    }

    owned->request.path = owned->path;
    owned->request.path_len = path_len;
    owned->request.tx_type = tx_type;
    owned->request.chain_id = chain_id;
    owned->request.nonce = nonce;
    owned->request.gas_limit = gas_limit;
    owned->request.gas_price = gas_price;
    owned->request.max_priority_fee_per_gas = max_priority_fee_per_gas;
    owned->request.max_fee_per_gas = max_fee_per_gas;
    owned->request.has_to = true;
    memcpy(owned->request.to, to, sizeof(owned->request.to));
    owned->request.value = value_len ? owned->value : NULL;
    owned->request.value_len = value_len;
    owned->request.data = data_len ? owned->data : NULL;
    owned->request.data_len = data_len;
    owned->request.allow_unknown_contract_call = allow_unknown_contract_call;

    return true;
}
#endif /* AMALGAMATED_BUILD */
