#ifndef AMALGAMATED_BUILD
#include "sign.h"

#include "authorize.h"
#include "digest.h"
#include "wallet.h"

#include <string.h>
#include <wally_crypto.h>

static bool ethereum_copy_path(const uint32_t* const path, const size_t path_len, wallet_core_path_t* const output)
{
    if (!path || path_len == 0 || path_len > WALLET_CORE_MAX_PATH_LEN || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    memcpy(output->parts, path, path_len * sizeof(path[0]));
    output->len = path_len;
    return true;
}

static bool ethereum_recovery_id_from_wally_signature(const uint8_t header, uint8_t* const recovery_id)
{
    if (!recovery_id) {
        return false;
    }

    if (header == 27 || header == 28) {
        *recovery_id = (uint8_t)(header - 27);
        return true;
    }
    if (header == 31 || header == 32) {
        *recovery_id = (uint8_t)(header - 31);
        return true;
    }
    return false;
}

static bool ethereum_signature_v(
    const ethereum_tx_preflight_request_t* const request, const uint8_t recovery_id, uint64_t* const v)
{
    if (!request || recovery_id > 1 || !v) {
        return false;
    }

    if (request->tx_type == ETHEREUM_TX_TYPE_EIP1559) {
        *v = recovery_id;
        return true;
    }

    if (request->tx_type != ETHEREUM_TX_TYPE_LEGACY || request->chain_id > (UINT64_MAX - 35U - recovery_id) / 2U) {
        return false;
    }

    *v = (2U * request->chain_id) + 35U + recovery_id;
    return true;
}

bool ethereum_sign_tx(const ethereum_tx_preflight_request_t* const request, ethereum_signature_t* const signature)
{
    if (!request || !signature) {
        return false;
    }

    wallet_core_path_t path;
    uint8_t derived_sender[ETHEREUM_ADDRESS_LEN];
    if (!ethereum_copy_path(request->path, request->path_len, &path)
        || !ethereum_wallet_address_from_path(&path, derived_sender, sizeof(derived_sender))) {
        return false;
    }

    ethereum_tx_preflight_request_t trusted_request = *request;
    trusted_request.sender_address = derived_sender;
    trusted_request.sender_address_len = sizeof(derived_sender);
    trusted_request.expected_sender_address = derived_sender;
    trusted_request.expected_sender_address_len = sizeof(derived_sender);

    chain_authorization_t authorization;
    chain_authorized_digest_t authorized_digest;
    uint8_t recoverable_signature[EC_SIGNATURE_RECOVERABLE_LEN];
    wally_bzero(&authorization, sizeof(authorization));
    wally_bzero(&authorized_digest, sizeof(authorized_digest));
    wally_bzero(recoverable_signature, sizeof(recoverable_signature));
    wally_bzero(signature, sizeof(*signature));

    uint8_t recovery_id = 0;
    const bool ok = ethereum_authorize_tx(&trusted_request, &authorization)
        && ethereum_tx_build_authorized_digest(&trusted_request, &authorization, &authorized_digest)
        && wallet_core_sign_digest_ecdsa_recoverable(&authorized_digest.path, authorized_digest.tx_digest,
            sizeof(authorized_digest.tx_digest), recoverable_signature, sizeof(recoverable_signature))
        && ethereum_recovery_id_from_wally_signature(recoverable_signature[0], &recovery_id)
        && ethereum_signature_v(&trusted_request, recovery_id, &signature->v);

    if (ok) {
        memcpy(signature->r, recoverable_signature + 1, sizeof(signature->r));
        memcpy(signature->s, recoverable_signature + 1 + sizeof(signature->r), sizeof(signature->s));
    } else {
        wally_bzero(signature, sizeof(*signature));
    }

    wally_bzero(&authorization, sizeof(authorization));
    wally_bzero(&authorized_digest, sizeof(authorized_digest));
    wally_bzero(recoverable_signature, sizeof(recoverable_signature));
    wally_bzero(derived_sender, sizeof(derived_sender));
    wally_bzero(&trusted_request, sizeof(trusted_request));
    wally_bzero(&path, sizeof(path));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
