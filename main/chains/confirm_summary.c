#ifndef AMALGAMATED_BUILD
#include "confirm_summary.h"

#include <string.h>
#include <wally_crypto.h>

void chain_confirm_summary_init(chain_confirm_summary_t* const summary, const chain_confirm_chain_t chain,
    const chain_confirm_operation_t operation, const uint32_t flags)
{
    if (!summary) {
        return;
    }
    wally_bzero(summary, sizeof(*summary));
    summary->chain = chain;
    summary->operation = operation;
    summary->flags = flags;
}

static chain_confirm_field_t* next_field(chain_confirm_summary_t* const summary)
{
    if (!summary || summary->num_fields >= CHAIN_CONFIRM_MAX_FIELDS) {
        return NULL;
    }
    return &summary->fields[summary->num_fields++];
}

bool chain_confirm_summary_add_u64(
    chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind, const uint64_t value)
{
    chain_confirm_field_t* const field = next_field(summary);
    if (!field) {
        return false;
    }
    field->kind = kind;
    field->value_type = CHAIN_CONFIRM_VALUE_U64;
    field->value.u64 = value;
    return true;
}

bool chain_confirm_summary_add_bytes(chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind,
    const uint8_t* const bytes, const size_t bytes_len)
{
    if ((!bytes && bytes_len) || bytes_len > CHAIN_CONFIRM_MAX_BYTES) {
        return false;
    }

    chain_confirm_field_t* const field = next_field(summary);
    if (!field) {
        return false;
    }
    field->kind = kind;
    field->value_type = CHAIN_CONFIRM_VALUE_BYTES;
    field->value.bytes.len = bytes_len;
    if (bytes_len) {
        memcpy(field->value.bytes.bytes, bytes, bytes_len);
    }
    return true;
}

bool chain_confirm_summary_add_path(chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind,
    const uint32_t* const path, const size_t path_len)
{
    if (!path || path_len == 0 || path_len > CHAIN_CONFIRM_MAX_PATH_LEN) {
        return false;
    }

    chain_confirm_field_t* const field = next_field(summary);
    if (!field) {
        return false;
    }
    field->kind = kind;
    field->value_type = CHAIN_CONFIRM_VALUE_PATH;
    field->value.path.len = path_len;
    memcpy(field->value.path.parts, path, path_len * sizeof(path[0]));
    return true;
}

bool chain_confirm_summary_add_text(
    chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind, const char* const text)
{
    if (!text || text[0] == '\0' || strnlen(text, CHAIN_CONFIRM_MAX_TEXT) >= CHAIN_CONFIRM_MAX_TEXT) {
        return false;
    }

    chain_confirm_field_t* const field = next_field(summary);
    if (!field) {
        return false;
    }
    field->kind = kind;
    field->value_type = CHAIN_CONFIRM_VALUE_TEXT;
    memcpy(field->value.text, text, strlen(text) + 1);
    return true;
}

bool chain_confirm_summary_has_field(
    const chain_confirm_summary_t* const summary, const chain_confirm_field_kind_t kind)
{
    if (!summary) {
        return false;
    }
    for (size_t i = 0; i < summary->num_fields; ++i) {
        if (summary->fields[i].kind == kind) {
            return true;
        }
    }
    return false;
}
#endif /* AMALGAMATED_BUILD */
