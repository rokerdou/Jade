#ifndef AMALGAMATED_BUILD
#include "chain_confirm.h"

#include "../chains/path.h"
#include "../jade_assert.h"
#include "../ui.h"

#include <stdio.h>
#include <string.h>

#define HEX_LINE_CHARS 16
#define DISPLAY_LINE_MAX 24

static const char* chain_name(const chain_confirm_chain_t chain)
{
    switch (chain) {
    case CHAIN_CONFIRM_CHAIN_ETHEREUM:
        return "Ethereum";
    case CHAIN_CONFIRM_CHAIN_TRON:
        return "Tron";
    }
    return "Unknown";
}

static const char* operation_name(const chain_confirm_operation_t operation)
{
    switch (operation) {
    case CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER:
        return "Native transfer";
    case CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER:
        return "Token transfer";
    case CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE:
        return "Token approve";
    case CHAIN_CONFIRM_OPERATION_CONTRACT_CALL:
        return "Contract call";
    }
    return "Unknown operation";
}

static const char* field_name(const chain_confirm_field_kind_t kind)
{
    switch (kind) {
    case CHAIN_CONFIRM_FIELD_PATH:
        return "Path";
    case CHAIN_CONFIRM_FIELD_CHAIN_ID:
        return "Chain ID";
    case CHAIN_CONFIRM_FIELD_NONCE:
        return "Nonce";
    case CHAIN_CONFIRM_FIELD_FROM:
        return "From";
    case CHAIN_CONFIRM_FIELD_OWNER:
        return "Owner";
    case CHAIN_CONFIRM_FIELD_TO:
        return "To";
    case CHAIN_CONFIRM_FIELD_AMOUNT:
        return "Amount";
    case CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT:
        return "Token Contract";
    case CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT:
        return "Token Recipient";
    case CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT:
        return "Token Amount";
    case CHAIN_CONFIRM_FIELD_MAX_FEE:
        return "Max Fee";
    case CHAIN_CONFIRM_FIELD_FEE_LIMIT:
        return "Fee Limit";
    case CHAIN_CONFIRM_FIELD_CALLDATA_HASH:
        return "Calldata Hash";
    }
    return "Field";
}

static char hex_digit(const uint8_t value) { return value < 10 ? (char)('0' + value) : (char)('a' + value - 10); }

static bool format_bytes_hex(
    const uint8_t* const bytes, const size_t bytes_len, char* const output, const size_t output_len)
{
    if ((!bytes && bytes_len) || !output || output_len < (2 * bytes_len) + 3) {
        return false;
    }

    output[0] = '0';
    output[1] = 'x';
    for (size_t i = 0; i < bytes_len; ++i) {
        output[2 + (2 * i)] = hex_digit(bytes[i] >> 4);
        output[3 + (2 * i)] = hex_digit(bytes[i] & 0x0f);
    }
    output[2 + (2 * bytes_len)] = '\0';
    return true;
}

static bool format_path(const chain_confirm_path_t* const path, char* const output, const size_t output_len)
{
    if (!path || path->len == 0 || path->len > CHAIN_CONFIRM_MAX_PATH_LEN || !output || output_len < 16) {
        return false;
    }

    size_t pos = 0;
    int ret = snprintf(output, output_len, "m");
    if (ret < 0 || (size_t)ret >= output_len) {
        return false;
    }
    pos = (size_t)ret;

    for (size_t i = 0; i < path->len; ++i) {
        const uint32_t part = path->parts[i];
        const uint32_t index = chain_path_unharden(part);
        ret = snprintf(
            output + pos, output_len - pos, "/%lu%s", (unsigned long)index, chain_path_is_hardened(part) ? "'" : "");
        if (ret < 0 || (size_t)ret >= output_len - pos) {
            return false;
        }
        pos += (size_t)ret;
    }
    return true;
}

static bool show_text_value(const char* const title, const char* const value)
{
    JADE_ASSERT(title);
    JADE_ASSERT(value);

    const char* message[] = { value };
    return await_continueback_activity(title, message, 1, true, NULL);
}

static bool show_hex_value(const char* const title, const uint8_t* const bytes, const size_t bytes_len)
{
    char hex[(2 * CHAIN_CONFIRM_MAX_BYTES) + 3];
    if (!format_bytes_hex(bytes, bytes_len, hex, sizeof(hex))) {
        return false;
    }

    char lines[5][DISPLAY_LINE_MAX];
    const char* message[5];
    size_t num_lines = 0;
    for (size_t offset = 0; hex[offset] != '\0' && num_lines < 5; offset += HEX_LINE_CHARS) {
        const int ret = snprintf(lines[num_lines], sizeof(lines[num_lines]), "%.*s", HEX_LINE_CHARS, hex + offset);
        if (ret < 0 || (size_t)ret >= sizeof(lines[num_lines])) {
            return false;
        }
        message[num_lines] = lines[num_lines];
        ++num_lines;
    }

    if (hex[num_lines * HEX_LINE_CHARS] != '\0') {
        return false;
    }
    return await_continueback_activity(title, message, num_lines, true, NULL);
}

static bool show_field(const chain_confirm_field_t* const field)
{
    if (!field) {
        return false;
    }

    const char* const title = field_name(field->kind);
    char value[96];
    if (field->value_type == CHAIN_CONFIRM_VALUE_U64) {
        const int ret = snprintf(value, sizeof(value), "%llu", (unsigned long long)field->value.u64);
        return ret > 0 && (size_t)ret < sizeof(value) && show_text_value(title, value);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_PATH) {
        return format_path(&field->value.path, value, sizeof(value)) && show_text_value(title, value);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_BYTES) {
        return show_hex_value(title, field->value.bytes.bytes, field->value.bytes.len);
    }
    return false;
}

static bool show_extra_risk_confirmation(const chain_confirm_summary_t* const summary)
{
    if ((summary->flags & CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM) == 0) {
        return true;
    }

    if ((summary->flags & CHAIN_CONFIRM_FLAG_APPROVAL) != 0) {
        const char* message[] = { "Token approval", "can spend funds.", "Review carefully." };
        return await_yesno_activity("High Risk", message, 3, false, NULL);
    }
    if ((summary->flags & CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT) != 0) {
        const char* message[] = { "Unknown contract", "Only calldata hash", "can be verified." };
        return await_yesno_activity("High Risk", message, 3, false, NULL);
    }
    const char* message[] = { "Extra review", "required." };
    return await_yesno_activity("High Risk", message, 2, false, NULL);
}

bool show_chain_confirm_summary_activity(const chain_confirm_summary_t* const summary)
{
    if (!summary || (summary->flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) == 0 || summary->num_fields == 0
        || summary->num_fields > CHAIN_CONFIRM_MAX_FIELDS) {
        return false;
    }

    const char* overview[] = { chain_name(summary->chain), operation_name(summary->operation), "Review on device." };
    if (!await_continueback_activity("Confirm Tx", overview, 3, true, NULL)) {
        return false;
    }

    if (!show_extra_risk_confirmation(summary)) {
        return false;
    }

    for (size_t i = 0; i < summary->num_fields; ++i) {
        if (!show_field(&summary->fields[i])) {
            return false;
        }
    }

    const char* final_message[]
        = { chain_name(summary->chain), operation_name(summary->operation), "Sign transaction?" };
    return await_yesno_activity("Final Confirm", final_message, 3, false, NULL);
}
#endif /* AMALGAMATED_BUILD */
