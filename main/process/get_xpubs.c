#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "process_utils.h"

void get_xpubs_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_xpub");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    // NOTE: for get-xpub accessing the root key (empty bip32 path array) *IS* allowed.
    size_t written = 0;
    uint32_t path[MAX_PATH_LEN];
    const size_t max_path_len = sizeof(path) / sizeof(path[0]);
    const bool has_path = rpc_get_bip32_path("path", &params, path, max_path_len, &written);
    if (!has_path) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid path from parameters");
        goto cleanup;
    }

    char pathstr[MAX_PATH_STR_LEN(MAX_PATH_LEN)];
    const bool path_only = false;
    if (!wallet_bip32_path_as_str(path, written, pathstr, sizeof(pathstr), path_only)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to convert path to string format");
        goto cleanup;
    }

    const char* question[] = { "Export xpub?", "Host can track", "wallet history." };
    if (!await_yesno_activity("Public Key", question, 3, false, NULL)) {
        JADE_LOGW("User declined to export xpub for path %s", pathstr);
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to export xpub");
        goto cleanup;
    }

    char* output = NULL;
    if (!wallet_get_xpub(network_id, path, written, &output) || !output) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Cannot get xpub for path");
        goto cleanup;
    }
    jade_process_wally_free_string_on_exit(process, output);

    uint8_t buf[256];
    jade_process_reply_to_message_result(&process->ctx, buf, sizeof(buf), output, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
