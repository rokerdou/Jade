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

static bool chain_confirm_field_equal(const chain_confirm_field_t* const lhs, const chain_confirm_field_t* const rhs)
{
    if (!lhs || !rhs || lhs->kind != rhs->kind || lhs->value_type != rhs->value_type) {
        return false;
    }

    if (lhs->value_type == CHAIN_CONFIRM_VALUE_U64) {
        return lhs->value.u64 == rhs->value.u64;
    }
    if (lhs->value_type == CHAIN_CONFIRM_VALUE_BYTES) {
        return lhs->value.bytes.len == rhs->value.bytes.len
            && memcmp(lhs->value.bytes.bytes, rhs->value.bytes.bytes, lhs->value.bytes.len) == 0;
    }
    if (lhs->value_type == CHAIN_CONFIRM_VALUE_PATH) {
        return lhs->value.path.len == rhs->value.path.len
            && lhs->value.path.len <= CHAIN_CONFIRM_MAX_PATH_LEN
            && memcmp(lhs->value.path.parts, rhs->value.path.parts,
                   lhs->value.path.len * sizeof(lhs->value.path.parts[0]))
                == 0;
    }
    if (lhs->value_type == CHAIN_CONFIRM_VALUE_TEXT) {
        const size_t lhs_len = strnlen(lhs->value.text, CHAIN_CONFIRM_MAX_TEXT);
        const size_t rhs_len = strnlen(rhs->value.text, CHAIN_CONFIRM_MAX_TEXT);
        return lhs_len < CHAIN_CONFIRM_MAX_TEXT && rhs_len < CHAIN_CONFIRM_MAX_TEXT && lhs_len == rhs_len
            && memcmp(lhs->value.text, rhs->value.text, lhs_len + 1U) == 0;
    }
    return false;
}

bool chain_confirm_summary_equal(const chain_confirm_summary_t* const lhs, const chain_confirm_summary_t* const rhs)
{
    if (!lhs || !rhs || lhs->chain != rhs->chain || lhs->operation != rhs->operation || lhs->flags != rhs->flags
        || lhs->num_fields != rhs->num_fields || lhs->num_fields > CHAIN_CONFIRM_MAX_FIELDS) {
        return false;
    }

    for (size_t i = 0; i < lhs->num_fields; ++i) {
        if (!chain_confirm_field_equal(&lhs->fields[i], &rhs->fields[i])) {
            return false;
        }
    }
    return true;
}
#endif /* AMALGAMATED_BUILD */
