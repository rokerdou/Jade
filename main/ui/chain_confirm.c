#ifndef AMALGAMATED_BUILD
#include "chain_confirm.h"

#include "../chains/path.h"
#include "../jade_assert.h"
#include "../ui.h"
#ifdef CONFIG_TREZOR_USB_HID
#include "../protocols/trezor/trace.h"
#endif

#include <stdio.h>
#include <string.h>

static const char* chain_name(const chain_confirm_chain_t chain)
{
    switch (chain) {
    case CHAIN_CONFIRM_CHAIN_ETHEREUM:
        return "Ethereum";
    case CHAIN_CONFIRM_CHAIN_BITCOIN:
        return "Bitcoin";
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
    case CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL:
        return "Token Symbol";
    case CHAIN_CONFIRM_FIELD_TOKEN_DECIMALS:
        return "Token Decimals";
    case CHAIN_CONFIRM_FIELD_TOKEN_NAME:
        return "Token Name";
    case CHAIN_CONFIRM_FIELD_MAX_FEE:
        return "Max Fee";
    case CHAIN_CONFIRM_FIELD_FEE:
        return "Fee";
    case CHAIN_CONFIRM_FIELD_FEE_LIMIT:
        return "Fee Limit";
    case CHAIN_CONFIRM_FIELD_CALLDATA_HASH:
        return "Calldata Hash";
    }
    return "Field";
}

#ifdef CONFIG_TREZOR_USB_HID
static const char* field_trace_stage(const chain_confirm_field_kind_t kind, const bool done)
{
    switch (kind) {
    case CHAIN_CONFIRM_FIELD_PATH:
        return done ? "ui:path_ok" : "ui:path";
    case CHAIN_CONFIRM_FIELD_CHAIN_ID:
        return done ? "ui:chain_ok" : "ui:chain";
    case CHAIN_CONFIRM_FIELD_NONCE:
        return done ? "ui:nonce_ok" : "ui:nonce";
    case CHAIN_CONFIRM_FIELD_FROM:
        return done ? "ui:from_ok" : "ui:from";
    case CHAIN_CONFIRM_FIELD_OWNER:
        return done ? "ui:owner_ok" : "ui:owner";
    case CHAIN_CONFIRM_FIELD_TO:
        return done ? "ui:to_ok" : "ui:to";
    case CHAIN_CONFIRM_FIELD_AMOUNT:
        return done ? "ui:amount_ok" : "ui:amount";
    case CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT:
        return done ? "ui:token_ctr_ok" : "ui:token_ctr";
    case CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT:
        return done ? "ui:token_rcpt_ok" : "ui:token_rcpt";
    case CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT:
        return done ? "ui:token_amt_ok" : "ui:token_amt";
    case CHAIN_CONFIRM_FIELD_TOKEN_SYMBOL:
        return done ? "ui:token_sym_ok" : "ui:token_sym";
    case CHAIN_CONFIRM_FIELD_TOKEN_DECIMALS:
        return done ? "ui:token_dec_ok" : "ui:token_dec";
    case CHAIN_CONFIRM_FIELD_TOKEN_NAME:
        return done ? "ui:token_name_ok" : "ui:token_name";
    case CHAIN_CONFIRM_FIELD_MAX_FEE:
        return done ? "ui:maxfee_ok" : "ui:maxfee";
    case CHAIN_CONFIRM_FIELD_FEE:
        return done ? "ui:fee_ok" : "ui:fee";
    case CHAIN_CONFIRM_FIELD_FEE_LIMIT:
        return done ? "ui:feelimit_ok" : "ui:feelimit";
    case CHAIN_CONFIRM_FIELD_CALLDATA_HASH:
        return done ? "ui:calldata_ok" : "ui:calldata";
    }
    return done ? "ui:field_ok" : "ui:field";
}
#endif

static char hex_digit(const uint8_t value) { return value < 10 ? (char)('0' + value) : (char)('a' + value - 10); }

static bool append_char(char* const output, const size_t output_len, size_t* const pos, const char c)
{
    if (!output || !pos || *pos + 1 >= output_len) {
        return false;
    }
    output[*pos] = c;
    ++(*pos);
    output[*pos] = '\0';
    return true;
}

static bool append_u64_dec(char* const output, const size_t output_len, size_t* const pos, uint64_t value)
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
        if (!append_char(output, output_len, pos, digits[--len])) {
            return false;
        }
    }
    return true;
}

static bool format_u64_dec(const uint64_t value, char* const output, const size_t output_len)
{
    if (!output || output_len == 0) {
        return false;
    }
    output[0] = '\0';
    size_t pos = 0;
    return append_u64_dec(output, output_len, &pos, value);
}

static bool copy_hex_line(char* const output, const size_t output_len, const char* const hex, const size_t offset)
{
    if (!output || output_len == 0 || !hex) {
        return false;
    }

    size_t pos = 0;
    while (hex[offset + pos] != '\0' && pos < CHAIN_CONFIRM_UI_HEX_LINE_CHARS) {
        if (pos + 1 >= output_len) {
            return false;
        }
        output[pos] = hex[offset + pos];
        ++pos;
    }
    output[pos] = '\0';
    return true;
}

static bool copy_text_line(char* const output, const size_t output_len, const char* const text, const size_t offset)
{
    if (!output || output_len == 0 || !text) {
        return false;
    }

    size_t pos = 0;
    while (text[offset + pos] != '\0' && pos < CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX - 1U) {
        output[pos] = text[offset + pos];
        ++pos;
    }
    output[pos] = '\0';
    return true;
}

static void init_blank_message_lines(
    char lines[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES][CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX])
{
    for (size_t i = 0; i < CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES; ++i) {
        lines[i][0] = ' ';
        lines[i][1] = '\0';
    }
}

#ifdef CONFIG_TREZOR_USB_HID
static char trace_printable_char(const char c)
{
    return (c >= 32 && c <= 126) ? c : '?';
}

static void trace_text_value(const char* const title, const char* const value)
{
    const size_t len = value ? strnlen(value, CHAIN_CONFIRM_MAX_TEXT + 1) : 0;
    const char tail = len > 0 ? trace_printable_char(value[len - 1]) : '?';
    trezor_trace_set_note("field=%s text_len=%lu tail=%c", title ? title : "?", (unsigned long)len, tail);
}

static void trace_hex_value(const char* const title, const size_t bytes_len, const char* const hex)
{
    const size_t len = hex ? strnlen(hex, (2 * CHAIN_CONFIRM_MAX_BYTES) + 3) : 0;
    const char tail = len > 0 ? trace_printable_char(hex[len - 1]) : '?';
    trezor_trace_set_note("field=%s bytes=%lu hex_len=%lu tail=%c", title ? title : "?", (unsigned long)bytes_len,
        (unsigned long)len, tail);
}

static void trace_hex_page(const char* const title, const unsigned int page, const size_t num_lines,
    const char lines[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES][CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX])
{
    size_t last_len = 0;
    char last_tail = '?';
    if (num_lines > 0) {
        last_len = strnlen(lines[num_lines - 1], CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX);
        if (last_len > 0) {
            last_tail = trace_printable_char(lines[num_lines - 1][last_len - 1]);
        }
    }
    trezor_trace_set_note("field=%s page=%u lines=%lu last_len=%lu tail=%c", title ? title : "?", page,
        (unsigned long)num_lines, (unsigned long)last_len, last_tail);
}
#endif

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

    output[0] = '\0';
    size_t pos = 0;
    if (!append_char(output, output_len, &pos, 'm')) {
        return false;
    }

    for (size_t i = 0; i < path->len; ++i) {
        const uint32_t part = path->parts[i];
        const uint32_t index = chain_path_unharden(part);
        if (!append_char(output, output_len, &pos, '/') || !append_u64_dec(output, output_len, &pos, index)
            || (chain_path_is_hardened(part) && !append_char(output, output_len, &pos, '\''))) {
            return false;
        }
    }
    return true;
}

static bool show_text_value(const char* const title, const char* const value)
{
    JADE_ASSERT(title);
    JADE_ASSERT(value);

#ifdef CONFIG_TREZOR_USB_HID
    trace_text_value(title, value);
#endif
    size_t offset = 0;
    unsigned int page = 1;
    while (value[offset] != '\0') {
        char lines[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES][CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX] = { { 0 } };
        init_blank_message_lines(lines);
        const char* message[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES] = { lines[0], lines[1], lines[2], lines[3] };
        size_t num_lines = 0;
        while (value[offset] != '\0' && num_lines < CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES) {
            if (!copy_text_line(lines[num_lines], sizeof(lines[num_lines]), value, offset)) {
                return false;
            }
            ++num_lines;
            offset += CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX - 1U;
        }
        if (num_lines == 0 || num_lines > CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES) {
            return false;
        }

        char page_title[32];
        const char* display_title = title;
        if (page > 1 || value[offset] != '\0') {
            const int ret = snprintf(page_title, sizeof(page_title), "%s %u", title, page);
            if (ret <= 0 || (size_t)ret >= sizeof(page_title)) {
                return false;
            }
            display_title = page_title;
        }
        if (!await_continueback_activity(display_title, message, CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES, true, NULL)) {
            return false;
        }
        ++page;
    }
    return true;
}

static bool show_hex_value(const char* const title, const uint8_t* const bytes, const size_t bytes_len)
{
    char hex[(2 * CHAIN_CONFIRM_MAX_BYTES) + 3];
    if (!format_bytes_hex(bytes, bytes_len, hex, sizeof(hex))) {
        return false;
    }
#ifdef CONFIG_TREZOR_USB_HID
    trace_hex_value(title, bytes_len, hex);
#endif

    size_t offset = 0;
    unsigned int page = 1;
    while (hex[offset] != '\0') {
        char lines[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES][CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX] = { { 0 } };
        init_blank_message_lines(lines);
        const char* message[CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES] = { lines[0], lines[1], lines[2], lines[3] };
        size_t num_lines = 0;
        while (hex[offset] != '\0' && num_lines < CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES) {
            if (!copy_hex_line(lines[num_lines], sizeof(lines[num_lines]), hex, offset)) {
                return false;
            }
            ++num_lines;
            offset += CHAIN_CONFIRM_UI_HEX_LINE_CHARS;
        }
        if (num_lines == 0 || num_lines > CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES) {
            return false;
        }
#ifdef CONFIG_TREZOR_USB_HID
        trace_hex_page(title, page, num_lines, lines);
#endif

        char page_title[32];
        const char* display_title = title;
        if (page > 1 || hex[offset] != '\0') {
            const int ret = snprintf(page_title, sizeof(page_title), "%s %u", title, page);
            if (ret <= 0 || (size_t)ret >= sizeof(page_title)) {
                return false;
            }
            display_title = page_title;
        }
        if (!await_continueback_activity(display_title, message, CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES, true, NULL)) {
            return false;
        }
        ++page;
    }
    return true;
}

static bool show_field(const chain_confirm_field_t* const field)
{
    if (!field) {
        return false;
    }

    const char* const title = field_name(field->kind);
#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_note("show field kind=%u type=%u", (unsigned int)field->kind, (unsigned int)field->value_type);
#endif
    char value[96];
    if (field->value_type == CHAIN_CONFIRM_VALUE_U64) {
        return format_u64_dec(field->value.u64, value, sizeof(value)) && show_text_value(title, value);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_PATH) {
        return format_path(&field->value.path, value, sizeof(value)) && show_text_value(title, value);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_TEXT) {
        return show_text_value(title, field->value.text);
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

#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_stage("ui:overview");
#endif
    const char* overview[] = { chain_name(summary->chain), operation_name(summary->operation), "Review on device." };
    if (!await_continueback_activity("Confirm Tx", overview, 3, true, NULL)) {
#ifdef CONFIG_TREZOR_USB_HID
        trezor_trace_set_stage("ui:overview_cancel");
#endif
        return false;
    }
#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_stage("ui:overview_ok");
#endif

#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_stage("ui:risk");
#endif
    if (!show_extra_risk_confirmation(summary)) {
#ifdef CONFIG_TREZOR_USB_HID
        trezor_trace_set_stage("ui:risk_cancel");
#endif
        return false;
    }
#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_stage("ui:risk_ok");
#endif

    size_t field_index = 0;
    while (field_index < summary->num_fields) {
#ifdef CONFIG_TREZOR_USB_HID
        trezor_trace_set_stage(field_trace_stage(summary->fields[field_index].kind, false));
#endif
        if (!show_field(&summary->fields[field_index])) {
#ifdef CONFIG_TREZOR_USB_HID
            trezor_trace_set_stage("ui:field_back");
#endif
            if (field_index == 0) {
#ifdef CONFIG_TREZOR_USB_HID
                trezor_trace_set_stage("ui:field_cancel");
#endif
                return false;
            }
            --field_index;
            continue;
        }
#ifdef CONFIG_TREZOR_USB_HID
        trezor_trace_set_stage(field_trace_stage(summary->fields[field_index].kind, true));
#endif
        ++field_index;
    }

#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_set_stage("ui:final");
#endif
    const char* final_message[]
        = { chain_name(summary->chain), operation_name(summary->operation), "Sign transaction?" };
    const bool accepted = await_signcancel_activity("Final Confirm", final_message, 3, true, NULL);
#ifdef CONFIG_TREZOR_USB_HID
    trezor_trace_checkpoint(accepted ? "ui:final_ok" : "ui:final_cancel", "accepted=%u", accepted ? 1U : 0U);
#endif
    return accepted;
}
#endif /* AMALGAMATED_BUILD */
