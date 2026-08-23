#ifndef AMALGAMATED_BUILD
#include "chain_confirm_format.h"

#include "chain_confirm.h"

bool chain_confirm_ui_copy_text_line(
    char* const output, const size_t output_len, const char* const text, const size_t text_len, const size_t offset,
    size_t* const consumed)
{
    if (!output || output_len == 0 || !text || offset > text_len || !consumed) {
        return false;
    }

    output[0] = '\0';
    *consumed = 0;
    while (offset + *consumed < text_len && text[offset + *consumed] != '\0'
        && *consumed < CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX - 1U) {
        if (*consumed + 1U >= output_len) {
            return false;
        }
        output[*consumed] = text[offset + *consumed];
        ++(*consumed);
    }
    output[*consumed] = '\0';
    return true;
}

bool chain_confirm_ui_copy_hex_line(
    char* const output, const size_t output_len, const char* const hex, const size_t hex_len, const size_t offset,
    size_t* const consumed)
{
    if (!output || output_len == 0 || !hex || offset > hex_len || !consumed) {
        return false;
    }

    output[0] = '\0';
    *consumed = 0;
    while (offset + *consumed < hex_len && hex[offset + *consumed] != '\0'
        && *consumed < CHAIN_CONFIRM_UI_HEX_LINE_CHARS) {
        if (*consumed + 1U >= output_len) {
            return false;
        }
        output[*consumed] = hex[offset + *consumed];
        ++(*consumed);
    }
    output[*consumed] = '\0';
    return true;
}
#endif /* AMALGAMATED_BUILD */
