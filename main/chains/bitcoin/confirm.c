#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include <string.h>

#define BITCOIN_AMOUNT_TEXT_MAX_LEN 32

static bool bitcoin_append_char(char* const output, const size_t output_len, size_t* const pos, const char c)
{
    if (!output || !pos || *pos + 1 >= output_len) {
        return false;
    }
    output[*pos] = c;
    ++(*pos);
    output[*pos] = '\0';
    return true;
}

static bool bitcoin_append_u64_dec(char* const output, const size_t output_len, size_t* const pos, uint64_t value)
{
    char digits[20];
    size_t len = 0;
    do {
        digits[len++] = (char)('0' + (value % 10U));
        value /= 10U;
    } while (value != 0 && len < sizeof(digits));

    if (value != 0) {
        return false;
    }
    while (len > 0) {
        if (!bitcoin_append_char(output, output_len, pos, digits[--len])) {
            return false;
        }
    }
    return true;
}

static bool bitcoin_append_str(char* const output, const size_t output_len, size_t* const pos, const char* const text)
{
    if (!text) {
        return false;
    }
    for (size_t i = 0; text[i] != '\0'; ++i) {
        if (!bitcoin_append_char(output, output_len, pos, text[i])) {
            return false;
        }
    }
    return true;
}

static bool bitcoin_format_sats(const uint64_t sats, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';
    size_t pos = 0;
    return bitcoin_append_u64_dec(output, output_len, &pos, sats)
        && bitcoin_append_str(output, output_len, &pos, " sats");
}

bool bitcoin_confirm_summary_from_request(const bitcoin_confirm_request_t* const request, chain_confirm_summary_t* const summary)
{
    if (!request || !summary || request->path_len == 0 || request->path_len > CHAIN_CONFIRM_MAX_PATH_LEN
        || request->to[0] == '\0') {
        return false;
    }

    char amount[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char change[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char fee[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    if (!bitcoin_format_sats(request->amount, amount, sizeof(amount))
        || !bitcoin_format_sats(request->change, change, sizeof(change))
        || !bitcoin_format_sats(request->fee, fee, sizeof(fee))) {
        return false;
    }

    chain_confirm_summary_init(
        summary, CHAIN_CONFIRM_CHAIN_BITCOIN, CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER, CHAIN_CONFIRM_FLAG_USER_CONFIRM);
    return chain_confirm_summary_add_path(
               summary, CHAIN_CONFIRM_FIELD_PATH, request->path, request->path_len)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TO, request->to)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_AMOUNT, amount)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_CHANGE, change)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_FEE, fee);
}
#endif /* AMALGAMATED_BUILD */
