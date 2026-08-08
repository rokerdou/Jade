#ifndef AMALGAMATED_BUILD
#include "authorization.h"

#include <string.h>
#include <wally_crypto.h>

#define CHAIN_AUTHORIZATION_SERIALIZED_MAX_LEN 768

typedef struct {
    uint8_t bytes[CHAIN_AUTHORIZATION_SERIALIZED_MAX_LEN];
    size_t len;
} chain_authorization_buffer_t;

static bool authorization_append(
    chain_authorization_buffer_t* const buffer, const uint8_t* const bytes, const size_t len)
{
    if (!buffer || (!bytes && len) || len > sizeof(buffer->bytes) - buffer->len) {
        return false;
    }
    if (len) {
        memcpy(buffer->bytes + buffer->len, bytes, len);
        buffer->len += len;
    }
    return true;
}

static bool authorization_append_u32(chain_authorization_buffer_t* const buffer, const uint32_t value)
{
    const uint8_t bytes[] = {
        (uint8_t)(value >> 24),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };
    return authorization_append(buffer, bytes, sizeof(bytes));
}

static bool authorization_append_u64(chain_authorization_buffer_t* const buffer, const uint64_t value)
{
    const uint8_t bytes[] = {
        (uint8_t)(value >> 56),
        (uint8_t)(value >> 48),
        (uint8_t)(value >> 40),
        (uint8_t)(value >> 32),
        (uint8_t)(value >> 24),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 8),
        (uint8_t)value,
    };
    return authorization_append(buffer, bytes, sizeof(bytes));
}

static bool authorization_path_matches(
    const wallet_core_path_t* const wallet_path, const chain_confirm_path_t* const confirm_path)
{
    if (!wallet_path || !confirm_path || wallet_path->len == 0 || wallet_path->len != confirm_path->len
        || wallet_path->len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    return memcmp(wallet_path->parts, confirm_path->parts, wallet_path->len * sizeof(wallet_path->parts[0])) == 0;
}

static bool authorization_summary_path_matches(const chain_authorization_t* const authorization)
{
    if (!authorization) {
        return false;
    }
    for (size_t i = 0; i < authorization->summary.num_fields; ++i) {
        const chain_confirm_field_t* const field = &authorization->summary.fields[i];
        if (field->kind == CHAIN_CONFIRM_FIELD_PATH) {
            return field->value_type == CHAIN_CONFIRM_VALUE_PATH
                && authorization_path_matches(&authorization->path, &field->value.path);
        }
    }
    return false;
}

static bool authorization_append_path(chain_authorization_buffer_t* const buffer, const wallet_core_path_t* const path)
{
    if (!path || path->len == 0 || path->len > WALLET_CORE_MAX_PATH_LEN
        || !authorization_append_u32(buffer, (uint32_t)path->len)) {
        return false;
    }
    for (size_t i = 0; i < path->len; ++i) {
        if (!authorization_append_u32(buffer, path->parts[i])) {
            return false;
        }
    }
    return true;
}

static bool authorization_append_confirm_path(
    chain_authorization_buffer_t* const buffer, const chain_confirm_path_t* const path)
{
    if (!path || path->len == 0 || path->len > CHAIN_CONFIRM_MAX_PATH_LEN
        || !authorization_append_u32(buffer, (uint32_t)path->len)) {
        return false;
    }
    for (size_t i = 0; i < path->len; ++i) {
        if (!authorization_append_u32(buffer, path->parts[i])) {
            return false;
        }
    }
    return true;
}

static bool authorization_append_field(
    chain_authorization_buffer_t* const buffer, const chain_confirm_field_t* const field)
{
    if (!field || !authorization_append_u32(buffer, (uint32_t)field->kind)
        || !authorization_append_u32(buffer, (uint32_t)field->value_type)) {
        return false;
    }

    if (field->value_type == CHAIN_CONFIRM_VALUE_U64) {
        return authorization_append_u64(buffer, field->value.u64);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_BYTES) {
        return field->value.bytes.len <= CHAIN_CONFIRM_MAX_BYTES
            && authorization_append_u32(buffer, (uint32_t)field->value.bytes.len)
            && authorization_append(buffer, field->value.bytes.bytes, field->value.bytes.len);
    }
    if (field->value_type == CHAIN_CONFIRM_VALUE_PATH) {
        return authorization_append_confirm_path(buffer, &field->value.path);
    }
    return false;
}

static bool authorization_serialize(
    const chain_authorization_t* const authorization, chain_authorization_buffer_t* const buffer)
{
    static const uint8_t domain[] = "JadeChainAuthorizationV1";
    if (!authorization || !buffer || !wallet_core_path_valid(&authorization->path)
        || (authorization->summary.flags & CHAIN_CONFIRM_FLAG_USER_CONFIRM) == 0
        || authorization->summary.num_fields == 0 || authorization->summary.num_fields > CHAIN_CONFIRM_MAX_FIELDS
        || !authorization_summary_path_matches(authorization)) {
        return false;
    }

    wally_bzero(buffer, sizeof(*buffer));
    if (!authorization_append(buffer, domain, sizeof(domain))
        || !authorization_append_u32(buffer, (uint32_t)authorization->summary.chain)
        || !authorization_append_u32(buffer, (uint32_t)authorization->summary.operation)
        || !authorization_append_u32(buffer, authorization->summary.flags)
        || !authorization_append_path(buffer, &authorization->path)
        || !authorization_append_u32(buffer, (uint32_t)authorization->summary.num_fields)) {
        return false;
    }

    for (size_t i = 0; i < authorization->summary.num_fields; ++i) {
        if (!authorization_append_field(buffer, &authorization->summary.fields[i])) {
            return false;
        }
    }
    return true;
}

bool chain_authorization_compute_binding(
    const chain_authorization_t* const authorization, uint8_t* const output, const size_t output_len)
{
    if (!output || output_len != CHAIN_AUTHORIZATION_BINDING_LEN) {
        return false;
    }

    chain_authorization_buffer_t buffer;
    if (!authorization_serialize(authorization, &buffer)) {
        return false;
    }

    const bool ok = wally_sha256(buffer.bytes, buffer.len, output, output_len) == WALLY_OK;
    wally_bzero(&buffer, sizeof(buffer));
    return ok;
}

bool chain_authorized_digest_init(const chain_authorization_t* const authorization, const uint8_t* const tx_digest,
    const size_t tx_digest_len, chain_authorized_digest_t* const output)
{
    static const uint8_t domain[] = "JadeChainAuthorizedDigestV1";
    if (!authorization || !tx_digest || tx_digest_len != CHAIN_AUTHORIZED_DIGEST_LEN || !output) {
        return false;
    }

    chain_authorized_digest_t local_output;
    wally_bzero(&local_output, sizeof(local_output));
    memcpy(&local_output.path, &authorization->path, sizeof(local_output.path));
    local_output.chain = authorization->summary.chain;
    memcpy(local_output.tx_digest, tx_digest, sizeof(local_output.tx_digest));
    if (!chain_authorization_compute_binding(
            authorization, local_output.authorization_binding, sizeof(local_output.authorization_binding))) {
        return false;
    }

    chain_authorization_buffer_t buffer;
    wally_bzero(&buffer, sizeof(buffer));
    const bool ok = authorization_append(&buffer, domain, sizeof(domain))
        && authorization_append(&buffer, local_output.authorization_binding, sizeof(local_output.authorization_binding))
        && authorization_append(&buffer, local_output.tx_digest, sizeof(local_output.tx_digest))
        && wally_sha256(buffer.bytes, buffer.len, local_output.signing_binding, sizeof(local_output.signing_binding))
            == WALLY_OK;
    wally_bzero(&buffer, sizeof(buffer));
    if (!ok) {
        wally_bzero(&local_output, sizeof(local_output));
        return false;
    }

    memcpy(output, &local_output, sizeof(*output));
    wally_bzero(&local_output, sizeof(local_output));
    return true;
}

bool chain_authorized_digest_matches_authorization(
    const chain_authorization_t* const authorization, const chain_authorized_digest_t* const authorized_digest)
{
    if (!authorization || !authorized_digest || authorized_digest->path.len == 0
        || authorized_digest->path.len != authorization->path.len
        || memcmp(authorized_digest->path.parts, authorization->path.parts,
               authorization->path.len * sizeof(authorization->path.parts[0]))
            != 0
        || authorized_digest->chain != authorization->summary.chain) {
        return false;
    }

    uint8_t authorization_binding[CHAIN_AUTHORIZATION_BINDING_LEN];
    bool ok = chain_authorization_compute_binding(authorization, authorization_binding, sizeof(authorization_binding))
        && memcmp(authorization_binding, authorized_digest->authorization_binding, sizeof(authorization_binding)) == 0;
    wally_bzero(authorization_binding, sizeof(authorization_binding));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
