#ifndef AMALGAMATED_BUILD
#include "authorize.h"

#include "../../ui/chain_confirm.h"
#include "confirm.h"
#include "wallet.h"

#include <string.h>
#include <wally_crypto.h>

static bool ethereum_authorize_copy_path(
    const uint32_t* const path, const size_t path_len, wallet_core_path_t* const output)
{
    if (!path || path_len == 0 || path_len > WALLET_CORE_MAX_PATH_LEN || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    memcpy(output->parts, path, path_len * sizeof(path[0]));
    output->len = path_len;
    return true;
}

bool ethereum_authorize_tx(
    const ethereum_tx_preflight_request_t* const request, chain_authorization_t* const authorization)
{
    if (!request || !authorization) {
        return false;
    }

    chain_authorization_t local_authorization;
    wally_bzero(&local_authorization, sizeof(local_authorization));
    if (!ethereum_authorize_copy_path(request->path, request->path_len, &local_authorization.path)) {
        return false;
    }

    uint8_t derived_sender[ETHEREUM_ADDRESS_LEN];
    if (!ethereum_wallet_address_from_path(&local_authorization.path, derived_sender, sizeof(derived_sender))) {
        return false;
    }

    ethereum_tx_preflight_request_t trusted_request = *request;
    trusted_request.sender_address = derived_sender;
    trusted_request.sender_address_len = sizeof(derived_sender);
    trusted_request.expected_sender_address = derived_sender;
    trusted_request.expected_sender_address_len = sizeof(derived_sender);

    ethereum_tx_preflight_result_t result;
    const bool ok = ethereum_tx_preflight(&trusted_request, &result)
        && ethereum_confirm_summary_from_preflight(&trusted_request, &result, &local_authorization.summary)
        && show_chain_confirm_summary_activity(&local_authorization.summary);
    wally_bzero(&result, sizeof(result));
    wally_bzero(derived_sender, sizeof(derived_sender));

    if (!ok) {
        wally_bzero(&local_authorization, sizeof(local_authorization));
        return false;
    }

    memcpy(authorization, &local_authorization, sizeof(*authorization));
    wally_bzero(&local_authorization, sizeof(local_authorization));
    return true;
}
#endif /* AMALGAMATED_BUILD */
