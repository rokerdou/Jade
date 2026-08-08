#ifndef AMALGAMATED_BUILD
#include "../chains/tron/address.h"
#include "../chains/tron/path.h"
#include "../chains/tron/wallet.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../wallet_core/wallet_core.h"

#include "process_utils.h"

#include <string.h>
#include <wally_crypto.h>

bool show_confirm_address_activity(const char* address, bool default_selection);

static bool get_tron_address_copy_path(
    const uint32_t* const path, const size_t path_len, wallet_core_path_t* const output)
{
    if (!path || !path_len || path_len > WALLET_CORE_MAX_PATH_LEN || !output) {
        return false;
    }

    memset(output, 0, sizeof(*output));
    output->len = path_len;
    memcpy(output->parts, path, path_len * sizeof(path[0]));
    return true;
}

void get_tron_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_tron_address");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    if (!rpc_get_bip32_path("path", &params, path, max_path_len, &path_len)
        || !tron_path_is_supported(path, path_len)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid TRON path");
        goto cleanup;
    }

    wallet_core_path_t wallet_path;
    if (!get_tron_address_copy_path(path, path_len, &wallet_path)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid TRON path length");
        goto cleanup;
    }

    uint8_t address[TRON_ADDRESS_LEN];
    if (!tron_wallet_address_from_path(&wallet_path, address, sizeof(address))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot derive TRON address");
        goto cleanup;
    }

    char address_str[TRON_BASE58_ADDRESS_MAX_LEN];
    if (!tron_address_to_base58(address, sizeof(address), address_str, sizeof(address_str))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot format TRON address");
        goto cleanup;
    }

    const bool default_selection = false;
    if (!show_confirm_address_activity(address_str, default_selection)) {
        JADE_LOGW("User declined to confirm TRON address");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to confirm TRON address");
        goto cleanup;
    }

    uint8_t buf[256];
    jade_process_reply_to_message_result(&process->ctx, buf, sizeof(buf), address_str, cbor_result_string_cb);
    JADE_LOGI("Success");

cleanup:
    wally_bzero(path, sizeof(path));
    return;
}
#endif // AMALGAMATED_BUILD
