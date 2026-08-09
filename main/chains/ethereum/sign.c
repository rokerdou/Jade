#ifndef AMALGAMATED_BUILD
#include "sign.h"

#include "authorize.h"
#include "digest.h"
#include "wallet.h"

#ifdef CONFIG_TREZOR_USB_HID
#include "../../protocols/trezor/trace.h"
#define ETH_SIGN_TRACE(stage) trezor_trace_set_stage(stage)
#define ETH_SIGN_NOTE(...) trezor_trace_set_note(__VA_ARGS__)
#define ETH_SIGN_CHECKPOINT(stage, ...) trezor_trace_checkpoint(stage, __VA_ARGS__)
#else
#define ETH_SIGN_TRACE(stage) ((void)0)
#define ETH_SIGN_NOTE(...) ((void)0)
#define ETH_SIGN_CHECKPOINT(stage, ...) ((void)0)
#endif

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
    ETH_SIGN_TRACE("sign:path_sender");
    ETH_SIGN_NOTE("sign path_len=%lu", (unsigned long)request->path_len);
    if (!ethereum_copy_path(request->path, request->path_len, &path)
        || !ethereum_wallet_address_from_path(&path, derived_sender, sizeof(derived_sender))) {
        ETH_SIGN_TRACE("sign:path_sender_fail");
        return false;
    }
    ETH_SIGN_TRACE("sign:path_sender_ok");

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
    ETH_SIGN_TRACE("sign:authorize");
    bool ok = ethereum_authorize_tx(&trusted_request, &authorization);
    ETH_SIGN_NOTE("sign authorize ok=%u fields=%lu", ok ? 1 : 0, (unsigned long)authorization.summary.num_fields);
    ETH_SIGN_TRACE(ok ? "sign:authorize_ok" : "sign:authorize_fail");
    if (ok) {
        ETH_SIGN_CHECKPOINT("sign:authorize_ok", "fields=%lu", (unsigned long)authorization.summary.num_fields);
    }
    if (ok) {
        ETH_SIGN_TRACE("sign:digest");
        ok = ethereum_tx_build_authorized_digest(&trusted_request, &authorization, &authorized_digest);
        ETH_SIGN_NOTE("sign digest ok=%u path_len=%lu", ok ? 1 : 0, (unsigned long)authorized_digest.path.len);
        ETH_SIGN_TRACE(ok ? "sign:digest_ok" : "sign:digest_fail");
        ETH_SIGN_CHECKPOINT(ok ? "sign:digest_ok" : "sign:digest_fail", "path_len=%lu",
            (unsigned long)authorized_digest.path.len);
    }
    if (ok) {
        ETH_SIGN_TRACE("sign:privsign");
        ok = wallet_core_sign_digest_ecdsa_recoverable(&authorized_digest.path, authorized_digest.tx_digest,
            sizeof(authorized_digest.tx_digest), recoverable_signature, sizeof(recoverable_signature));
        ETH_SIGN_NOTE("sign privsign ok=%u", ok ? 1 : 0);
        ETH_SIGN_TRACE(ok ? "sign:privsign_ok" : "sign:privsign_fail");
        ETH_SIGN_CHECKPOINT(ok ? "sign:privsign_ok" : "sign:privsign_fail", "ok=%u", ok ? 1U : 0U);
    }
    if (ok) {
        ETH_SIGN_TRACE("sign:recovery");
        ok = ethereum_recovery_id_from_wally_signature(recoverable_signature[0], &recovery_id)
            && ethereum_signature_v(&trusted_request, recovery_id, &signature->v);
        ETH_SIGN_NOTE("sign recovery ok=%u recid=%u", ok ? 1 : 0, (unsigned int)recovery_id);
        ETH_SIGN_TRACE(ok ? "sign:recovery_ok" : "sign:recovery_fail");
        ETH_SIGN_CHECKPOINT(ok ? "sign:recovery_ok" : "sign:recovery_fail", "recid=%u",
            (unsigned int)recovery_id);
    }

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
