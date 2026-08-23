#ifndef AMALGAMATED_BUILD
#include "authorize.h"

#include "../../ui/chain_confirm.h"
#include "confirm.h"
#include "wallet.h"

#include <string.h>
#include <wally_crypto.h>

static bool tron_authorize_copy_path(
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

bool tron_authorize_tx_ex(const tron_tx_preflight_request_t* const request, chain_authorization_t* const authorization,
    const bool free_managed_activities)
{
    if (!request || !authorization) {
        return false;
    }

    chain_authorization_t local_authorization;
    wally_bzero(&local_authorization, sizeof(local_authorization));
    if (!tron_authorize_copy_path(request->path, request->path_len, &local_authorization.path)) {
        return false;
    }

    uint8_t derived_signer[TRON_ADDRESS_LEN];
    if (!tron_wallet_address_from_path(&local_authorization.path, derived_signer, sizeof(derived_signer))) {
        return false;
    }

    tron_tx_preflight_request_t trusted_request = *request;
    trusted_request.signer_address = derived_signer;
    trusted_request.signer_address_len = sizeof(derived_signer);

    tron_tx_preflight_result_t result;
    const bool ok = tron_tx_preflight(&trusted_request, &result)
        && tron_confirm_summary_from_preflight(&trusted_request, &result, &local_authorization.summary)
        && show_chain_confirm_summary_activity_ex(&local_authorization.summary, free_managed_activities);
    wally_bzero(&result, sizeof(result));
    wally_bzero(derived_signer, sizeof(derived_signer));

    if (!ok) {
        wally_bzero(&local_authorization, sizeof(local_authorization));
        return false;
    }

    memcpy(authorization, &local_authorization, sizeof(*authorization));
    wally_bzero(&local_authorization, sizeof(local_authorization));
    return true;
}

bool tron_authorize_tx(const tron_tx_preflight_request_t* const request, chain_authorization_t* const authorization)
{
    return tron_authorize_tx_ex(request, authorization, false);
}
#endif /* AMALGAMATED_BUILD */
