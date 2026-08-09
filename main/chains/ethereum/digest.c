#ifndef AMALGAMATED_BUILD
#include "digest.h"

#include "../../crypto/keccak256.h"
#include "confirm.h"

#ifdef CONFIG_TREZOR_USB_HID
#include "../../protocols/trezor/trace.h"
#define ETH_DIGEST_TRACE(stage) trezor_trace_set_stage(stage)
#else
#define ETH_DIGEST_TRACE(stage) ((void)0)
#endif

#include <stdlib.h>
#include <string.h>
#include <wally_crypto.h>

#define ETHEREUM_RLP_STRING_BASE 0x80
#define ETHEREUM_RLP_LIST_BASE 0xc0
#define ETHEREUM_TYPED_TX_EIP1559 0x02

typedef struct {
    uint8_t* bytes;
    size_t len;
    size_t cap;
} ethereum_rlp_writer_t;

static bool ethereum_rlp_append(ethereum_rlp_writer_t* const writer, const uint8_t* const bytes, const size_t len)
{
    if (!writer || (!bytes && len) || len > writer->cap - writer->len) {
        return false;
    }
    if (len) {
        memcpy(writer->bytes + writer->len, bytes, len);
        writer->len += len;
    }
    return true;
}

static size_t ethereum_rlp_u64_size(uint64_t value)
{
    size_t len = 0;
    while (value != 0) {
        ++len;
        value >>= 8;
    }
    return len;
}

static bool ethereum_rlp_u64_bytes(
    uint64_t value, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written) {
        return false;
    }

    const size_t len = ethereum_rlp_u64_size(value);
    if (len > output_len) {
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        output[len - 1 - i] = (uint8_t)value;
        value >>= 8;
    }
    *written = len;
    return true;
}

static bool ethereum_rlp_scalar_valid(const uint8_t* const bytes, const size_t len)
{
    return (bytes || len == 0) && len <= EVM_ABI_WORD_LEN && (len == 0 || bytes[0] != 0);
}

static size_t ethereum_rlp_header_len(const size_t payload_len, const uint8_t* const data_start)
{
    if (payload_len == 1 && data_start && data_start[0] <= 0x7f) {
        return 0;
    }
    if (payload_len <= 55) {
        return 1;
    }
    return 1 + ethereum_rlp_u64_size(payload_len);
}

static size_t ethereum_rlp_item_len(const uint8_t* const bytes, const size_t len)
{
    return ethereum_rlp_header_len(len, bytes) + len;
}

static bool ethereum_rlp_write_header(ethereum_rlp_writer_t* const writer, const size_t payload_len,
    const uint8_t header_base, const uint8_t* const data_start)
{
    if (payload_len == 1 && data_start && data_start[0] <= 0x7f) {
        return true;
    }
    if (payload_len <= 55) {
        const uint8_t header = (uint8_t)(header_base + payload_len);
        return ethereum_rlp_append(writer, &header, sizeof(header));
    }

    uint8_t len_bytes[sizeof(size_t)];
    size_t len_bytes_len = 0;
    if (!ethereum_rlp_u64_bytes(payload_len, len_bytes, sizeof(len_bytes), &len_bytes_len) || len_bytes_len > 8) {
        return false;
    }

    const uint8_t header = (uint8_t)(header_base + 55 + len_bytes_len);
    return ethereum_rlp_append(writer, &header, sizeof(header))
        && ethereum_rlp_append(writer, len_bytes, len_bytes_len);
}

static bool ethereum_rlp_write_bytes(ethereum_rlp_writer_t* const writer, const uint8_t* const bytes, const size_t len)
{
    return (bytes || len == 0) && ethereum_rlp_write_header(writer, len, ETHEREUM_RLP_STRING_BASE, bytes)
        && ethereum_rlp_append(writer, bytes, len);
}

static bool ethereum_rlp_write_u64(ethereum_rlp_writer_t* const writer, const uint64_t value)
{
    uint8_t bytes[sizeof(uint64_t)];
    size_t len = 0;
    return ethereum_rlp_u64_bytes(value, bytes, sizeof(bytes), &len) && ethereum_rlp_write_bytes(writer, bytes, len);
}

static bool ethereum_rlp_write_empty_access_list(ethereum_rlp_writer_t* const writer)
{
    return ethereum_rlp_write_header(writer, 0, ETHEREUM_RLP_LIST_BASE, NULL);
}

static size_t ethereum_rlp_u64_item_len(const uint64_t value)
{
    uint8_t bytes[sizeof(uint64_t)];
    size_t len = 0;
    if (!ethereum_rlp_u64_bytes(value, bytes, sizeof(bytes), &len)) {
        return 0;
    }
    return ethereum_rlp_item_len(bytes, len);
}

static bool ethereum_tx_digest_request_valid(const ethereum_tx_preflight_request_t* const request)
{
    if (!request || request->tx_type == ETHEREUM_TX_TYPE_EIP2930
        || !ethereum_rlp_scalar_valid(request->value, request->value_len) || (!request->data && request->data_len)
        || request->data_len > ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN || !request->has_to) {
        return false;
    }
    if (request->tx_type == ETHEREUM_TX_TYPE_LEGACY) {
        return request->chain_id != 0 && request->gas_limit != 0 && request->gas_price != 0;
    }
    if (request->tx_type == ETHEREUM_TX_TYPE_EIP1559) {
        return request->chain_id != 0 && request->gas_limit != 0 && request->max_fee_per_gas != 0
            && request->max_priority_fee_per_gas <= request->max_fee_per_gas;
    }
    return false;
}

static size_t ethereum_tx_legacy_payload_len(const ethereum_tx_preflight_request_t* const request)
{
    return ethereum_rlp_u64_item_len(request->nonce) + ethereum_rlp_u64_item_len(request->gas_price)
        + ethereum_rlp_u64_item_len(request->gas_limit)
        + ethereum_rlp_item_len(request->has_to ? request->to : NULL, request->has_to ? sizeof(request->to) : 0)
        + ethereum_rlp_item_len(request->value, request->value_len)
        + ethereum_rlp_item_len(request->data, request->data_len) + ethereum_rlp_u64_item_len(request->chain_id)
        + ethereum_rlp_u64_item_len(0) + ethereum_rlp_u64_item_len(0);
}

static size_t ethereum_tx_eip1559_payload_len(const ethereum_tx_preflight_request_t* const request)
{
    return ethereum_rlp_u64_item_len(request->chain_id) + ethereum_rlp_u64_item_len(request->nonce)
        + ethereum_rlp_u64_item_len(request->max_priority_fee_per_gas)
        + ethereum_rlp_u64_item_len(request->max_fee_per_gas) + ethereum_rlp_u64_item_len(request->gas_limit)
        + ethereum_rlp_item_len(request->has_to ? request->to : NULL, request->has_to ? sizeof(request->to) : 0)
        + ethereum_rlp_item_len(request->value, request->value_len)
        + ethereum_rlp_item_len(request->data, request->data_len) + 1;
}

static bool ethereum_tx_write_legacy_payload(
    const ethereum_tx_preflight_request_t* const request, ethereum_rlp_writer_t* const writer)
{
    const size_t payload_len = ethereum_tx_legacy_payload_len(request);
    return ethereum_rlp_write_header(writer, payload_len, ETHEREUM_RLP_LIST_BASE, NULL)
        && ethereum_rlp_write_u64(writer, request->nonce) && ethereum_rlp_write_u64(writer, request->gas_price)
        && ethereum_rlp_write_u64(writer, request->gas_limit)
        && ethereum_rlp_write_bytes(
            writer, request->has_to ? request->to : NULL, request->has_to ? sizeof(request->to) : 0)
        && ethereum_rlp_write_bytes(writer, request->value, request->value_len)
        && ethereum_rlp_write_bytes(writer, request->data, request->data_len)
        && ethereum_rlp_write_u64(writer, request->chain_id) && ethereum_rlp_write_u64(writer, 0)
        && ethereum_rlp_write_u64(writer, 0);
}

static bool ethereum_tx_write_eip1559_payload(
    const ethereum_tx_preflight_request_t* const request, ethereum_rlp_writer_t* const writer)
{
    const uint8_t tx_type = ETHEREUM_TYPED_TX_EIP1559;
    const size_t payload_len = ethereum_tx_eip1559_payload_len(request);
    return ethereum_rlp_append(writer, &tx_type, sizeof(tx_type))
        && ethereum_rlp_write_header(writer, payload_len, ETHEREUM_RLP_LIST_BASE, NULL)
        && ethereum_rlp_write_u64(writer, request->chain_id) && ethereum_rlp_write_u64(writer, request->nonce)
        && ethereum_rlp_write_u64(writer, request->max_priority_fee_per_gas)
        && ethereum_rlp_write_u64(writer, request->max_fee_per_gas)
        && ethereum_rlp_write_u64(writer, request->gas_limit)
        && ethereum_rlp_write_bytes(
            writer, request->has_to ? request->to : NULL, request->has_to ? sizeof(request->to) : 0)
        && ethereum_rlp_write_bytes(writer, request->value, request->value_len)
        && ethereum_rlp_write_bytes(writer, request->data, request->data_len)
        && ethereum_rlp_write_empty_access_list(writer);
}

bool ethereum_tx_signing_payload(const ethereum_tx_preflight_request_t* const request, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!ethereum_tx_digest_request_valid(request) || !output || !written) {
        return false;
    }

    ethereum_rlp_writer_t writer = { .bytes = output, .cap = output_len, .len = 0 };
    const bool ok = request->tx_type == ETHEREUM_TX_TYPE_LEGACY ? ethereum_tx_write_legacy_payload(request, &writer)
                                                                : ethereum_tx_write_eip1559_payload(request, &writer);
    if (!ok) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

bool ethereum_tx_signing_hash(
    const ethereum_tx_preflight_request_t* const request, uint8_t* const output, const size_t output_len)
{
    if (!output || output_len != ETHEREUM_TX_SIGNING_HASH_LEN) {
        return false;
    }

    uint8_t* const payload = malloc(ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN);
    if (!payload) {
        return false;
    }

    size_t payload_len = 0;
    const bool ok = ethereum_tx_signing_payload(request, payload, ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN, &payload_len)
        && keccak256(payload, payload_len, output, output_len);
    wally_bzero(payload, ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN);
    free(payload);
    return ok;
}

bool ethereum_tx_build_authorized_digest(const ethereum_tx_preflight_request_t* const request,
    const chain_authorization_t* const authorization, chain_authorized_digest_t* const output)
{
    if (!request || !authorization || !output || !request->path || request->path_len == 0
        || request->path_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }

    ethereum_tx_preflight_result_t result;
    chain_authorization_t recomputed_authorization;
    wally_bzero(&result, sizeof(result));
    wally_bzero(&recomputed_authorization, sizeof(recomputed_authorization));

    uint8_t expected_binding[CHAIN_AUTHORIZATION_BINDING_LEN];
    uint8_t actual_binding[CHAIN_AUTHORIZATION_BINDING_LEN];
    uint8_t digest[ETHEREUM_TX_SIGNING_HASH_LEN];
    bool bindings_match = false;
    bool digest_ok = false;

    ETH_DIGEST_TRACE("digest:preflight");
    bool recompute_ok = ethereum_tx_preflight(request, &result);
    ETH_DIGEST_TRACE(recompute_ok ? "digest:preflight_ok" : "digest:preflight_fail");
    if (recompute_ok) {
        ETH_DIGEST_TRACE("digest:summary");
        recompute_ok = ethereum_confirm_summary_from_preflight(request, &result, &recomputed_authorization.summary);
        ETH_DIGEST_TRACE(recompute_ok ? "digest:summary_ok" : "digest:summary_fail");
    }

    if (recompute_ok) {
        memcpy(recomputed_authorization.path.parts, request->path, request->path_len * sizeof(request->path[0]));
        recomputed_authorization.path.len = request->path_len;
        ETH_DIGEST_TRACE("digest:binding");
        bindings_match
            = chain_authorization_compute_binding(&recomputed_authorization, expected_binding, sizeof(expected_binding))
            && chain_authorization_compute_binding(authorization, actual_binding, sizeof(actual_binding))
            && memcmp(expected_binding, actual_binding, sizeof(expected_binding)) == 0;
        ETH_DIGEST_TRACE(bindings_match ? "digest:binding_ok" : "digest:binding_fail");

        if (bindings_match) {
            ETH_DIGEST_TRACE("digest:hash");
            digest_ok = ethereum_tx_signing_hash(request, digest, sizeof(digest));
            ETH_DIGEST_TRACE(digest_ok ? "digest:hash_ok" : "digest:hash_fail");
        }
        if (digest_ok) {
            ETH_DIGEST_TRACE("digest:init_auth");
            digest_ok = chain_authorized_digest_init(authorization, digest, sizeof(digest), output);
            ETH_DIGEST_TRACE(digest_ok ? "digest:init_ok" : "digest:init_fail");
        }
    }

    wally_bzero(&result, sizeof(result));
    wally_bzero(&recomputed_authorization, sizeof(recomputed_authorization));
    wally_bzero(digest, sizeof(digest));
    wally_bzero(expected_binding, sizeof(expected_binding));
    wally_bzero(actual_binding, sizeof(actual_binding));
    return digest_ok;
}
#endif /* AMALGAMATED_BUILD */
