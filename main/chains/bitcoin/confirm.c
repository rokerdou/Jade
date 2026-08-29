#ifndef AMALGAMATED_BUILD
#include "confirm.h"

#include <string.h>

#define BITCOIN_AMOUNT_TEXT_MAX_LEN 40
#define BITCOIN_SATS_PER_BTC 100000000ULL
#define BITCOIN_DECIMALS 8
#define BITCOIN_LOCKTIME_THRESHOLD 500000000U

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

static bool bitcoin_format_amount(const uint64_t sats, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';

    const uint64_t whole = sats / BITCOIN_SATS_PER_BTC;
    uint64_t fractional = sats % BITCOIN_SATS_PER_BTC;
    size_t pos = 0;
    if (!bitcoin_append_u64_dec(output, output_len, &pos, whole)) {
        return false;
    }

    if (fractional != 0) {
        char fractional_digits[BITCOIN_DECIMALS];
        for (size_t i = 0; i < BITCOIN_DECIMALS; ++i) {
            fractional_digits[BITCOIN_DECIMALS - 1U - i] = (char)('0' + (fractional % 10U));
            fractional /= 10U;
        }
        size_t fractional_len = BITCOIN_DECIMALS;
        while (fractional_len > 0 && fractional_digits[fractional_len - 1U] == '0') {
            --fractional_len;
        }
        if (!bitcoin_append_char(output, output_len, &pos, '.')) {
            return false;
        }
        for (size_t i = 0; i < fractional_len; ++i) {
            if (!bitcoin_append_char(output, output_len, &pos, fractional_digits[i])) {
                return false;
            }
        }
    }

    return bitcoin_append_str(output, output_len, &pos, " BTC");
}

static bool bitcoin_format_fee_rate(const uint64_t sats_per_vbyte, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';
    size_t pos = 0;
    return bitcoin_append_u64_dec(output, output_len, &pos, sats_per_vbyte)
        && bitcoin_append_str(output, output_len, &pos, " sat/vB");
}

static bool bitcoin_append_hex_u32(char* const output, const size_t output_len, size_t* const pos, const uint32_t value)
{
    static const char hex[] = "0123456789abcdef";
    if (!bitcoin_append_str(output, output_len, pos, "0x")) {
        return false;
    }
    for (int shift = 28; shift >= 0; shift -= 4) {
        if (!bitcoin_append_char(output, output_len, pos, hex[(value >> shift) & 0x0fU])) {
            return false;
        }
    }
    return true;
}

static bool bitcoin_format_tx_flags(
    const uint32_t lock_time, const uint32_t sequence, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';
    size_t pos = 0;
    if (sequence < 0xfffffffeU && !bitcoin_append_str(output, output_len, &pos, "RBF")) {
        return false;
    } else if (sequence == 0xfffffffeU && !bitcoin_append_str(output, output_len, &pos, "Locktime")) {
        return false;
    }
    if (lock_time != 0) {
        if (pos != 0 && !bitcoin_append_str(output, output_len, &pos, ", ")) {
            return false;
        }
        const char* const prefix = lock_time < BITCOIN_LOCKTIME_THRESHOLD ? "block " : "unix ";
        if (!bitcoin_append_str(output, output_len, &pos, prefix)
            || !bitcoin_append_u64_dec(output, output_len, &pos, lock_time)) {
            return false;
        }
    }
    if (pos == 0 && sequence != UINT32_MAX) {
        return bitcoin_append_str(output, output_len, &pos, "seq ")
            && bitcoin_append_hex_u32(output, output_len, &pos, sequence);
    }
    return true;
}

bool bitcoin_confirm_summary_from_request(
    const bitcoin_confirm_request_t* const request, chain_confirm_summary_t* const summary)
{
    if (!request || !summary || request->path_len == 0 || request->path_len > CHAIN_CONFIRM_MAX_PATH_LEN
        || request->to[0] == '\0') {
        return false;
    }

    char amount[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char self[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char change[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char fee[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char fee_rate[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    char tx_flags[BITCOIN_AMOUNT_TEXT_MAX_LEN];
    if (!bitcoin_format_amount(request->amount, amount, sizeof(amount))
        || !bitcoin_format_amount(request->self, self, sizeof(self))
        || !bitcoin_format_amount(request->change, change, sizeof(change))
        || !bitcoin_format_amount(request->fee, fee, sizeof(fee))
        || !bitcoin_format_fee_rate(request->fee_rate_sats_per_vbyte, fee_rate, sizeof(fee_rate))
        || ((request->lock_time != 0 || request->sequence != UINT32_MAX)
            && !bitcoin_format_tx_flags(request->lock_time, request->sequence, tx_flags, sizeof(tx_flags)))) {
        return false;
    }

    chain_confirm_summary_init(
        summary, CHAIN_CONFIRM_CHAIN_BITCOIN, CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER, CHAIN_CONFIRM_FLAG_USER_CONFIRM);
    bool ok = chain_confirm_summary_add_path(summary, CHAIN_CONFIRM_FIELD_PATH, request->path, request->path_len);
    if (ok && request->policy[0] != '\0') {
        ok = chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_POLICY, request->policy);
    }
    ok = ok && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TO, request->to)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_AMOUNT, amount);
    if (ok && request->self > 0) {
        ok = chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_SELF, self);
    }
    ok = ok && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_CHANGE, change)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_FEE, fee)
        && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_FEE_RATE, fee_rate);
    if (ok && (request->lock_time != 0 || request->sequence != UINT32_MAX)) {
        ok = chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TX_FLAGS, tx_flags);
    }
    return ok;
}
#endif /* AMALGAMATED_BUILD */
