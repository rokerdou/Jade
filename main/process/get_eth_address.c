#ifndef AMALGAMATED_BUILD
#include "../chains/ethereum/address.h"
#include "../chains/ethereum/path.h"
#include "../chains/ethereum/wallet.h"
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../wallet_core/wallet_core.h"

#include "process_utils.h"

#include <string.h>
#include <wally_crypto.h>

bool show_confirm_address_activity(const char* address, bool default_selection);

static bool get_eth_address_copy_path(
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

void get_eth_address_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_eth_address");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    uint32_t path[MAX_PATH_LEN];
    size_t path_len = 0;
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    if (!rpc_get_bip32_path("path", &params, path, max_path_len, &path_len)
        || !ethereum_path_is_supported(path, path_len)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid Ethereum path");
        goto cleanup;
    }

    wallet_core_path_t wallet_path;
    if (!get_eth_address_copy_path(path, path_len, &wallet_path)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid Ethereum path length");
        goto cleanup;
    }

    uint8_t address[ETHEREUM_ADDRESS_LEN];
    if (!ethereum_wallet_address_from_path(&wallet_path, address, sizeof(address))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot derive Ethereum address");
        goto cleanup;
    }

    char address_str[ETHEREUM_CHECKSUM_ADDRESS_STRING_LEN];
    if (!ethereum_address_to_checksum_string(address, sizeof(address), address_str, sizeof(address_str))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot format Ethereum address");
        goto cleanup;
    }

    const bool default_selection = false;
    if (!show_confirm_address_activity(address_str, default_selection)) {
        JADE_LOGW("User declined to confirm Ethereum address");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to confirm Ethereum address");
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
