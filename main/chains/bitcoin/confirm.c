#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include <stdio.h>
#include <string.h>

#define BITCOIN_AMOUNT_TEXT_MAX_LEN 32

static bool bitcoin_format_sats(const uint64_t sats, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    const int ret = snprintf(output, output_len, "%llu sats", (unsigned long long)sats);
    return ret > 0 && (size_t)ret < output_len;
}

bool bitcoin_confirm_summary_from_request(const bitcoin_confirm_request_t* const request, chain_confirm_summary_t* const summary)
{
    if (!request || !summary || request->path_len == 0 || request->path_len > CHAIN_CONFIRM_MAX_PATH_LEN
        || request->to[0] == '\0') {
        return false;
    }

    char amount[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char fee[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    if (!bitcoin_format_sats(request->amount, amount, sizeof(amount))
        || !bitcoin_format_sats(request->fee, fee, sizeof(fee))) {
        return false;
    }

    chain_confirm_summary_init(
        summary, CHAIN_CONFIRM_CHAIN_BITCOIN, CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER, CHAIN_CONFIRM_FLAG_USER_CONFIRM);
    return chain_confirm_summary_add_path(
               summary, CHAIN_CONFIRM_FIELD_PATH, request->path, request->path_len)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TO, request->to)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_AMOUNT, amount)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_FEE, fee);
}
#endif /* AMALGAMATED_BUILD */
