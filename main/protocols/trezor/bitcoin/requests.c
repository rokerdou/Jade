#ifndef AMALGAMATED_BUILD
#include "requests.h"

#include "../protobuf.h"

#include <stdlib.h>
#include <wally_crypto.h>

bool trezor_bitcoin_tx_request_encode(const trezor_bitcoin_request_type_t request_type, const bool has_request_index,
    const uint32_t request_index, uint8_t* const output, const size_t output_len, size_t* const written)
{
    return trezor_bitcoin_tx_request_encode_with_tx_hash(
        request_type, has_request_index, request_index, NULL, 0, output, output_len, written);
}

bool trezor_bitcoin_tx_request_encode_with_tx_hash(const trezor_bitcoin_request_type_t request_type,
    const bool has_request_index, const uint32_t request_index, const uint8_t* const tx_hash,
    const size_t tx_hash_len, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || request_type > TREZOR_BITCOIN_REQUEST_TXPAYMENTREQ) {
        return false;
    }
    if ((tx_hash && tx_hash_len != SHA256_LEN) || (!tx_hash && tx_hash_len != 0)
        || (tx_hash && request_type == TREZOR_BITCOIN_REQUEST_TXFINISHED)) {
        return false;
    }

    const bool write_details = request_type != TREZOR_BITCOIN_REQUEST_TXFINISHED;
    uint8_t details[64];
    trezor_protobuf_writer_t details_writer;
    trezor_protobuf_writer_init(&details_writer, details, sizeof(details));
    if (has_request_index && !trezor_protobuf_write_varint_field(&details_writer, 1, request_index)) {
        return false;
    }
    if (tx_hash && !trezor_protobuf_write_bytes_field(&details_writer, 2, tx_hash, tx_hash_len)) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_varint_field(&writer, 1, request_type)
        || (write_details
            && !trezor_protobuf_write_bytes_field(&writer, 2, details, details_writer.len))) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

static bool trezor_bitcoin_tx_request_encode_signed_part(const trezor_bitcoin_request_type_t request_type,
    const uint32_t signature_index, const uint8_t* const signature, const size_t signature_len,
    const uint8_t* const serialized_tx, const size_t serialized_tx_len, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!signature || signature_len == 0 || signature_len > TREZOR_BITCOIN_SIGNATURE_MAX_LEN
        || (!serialized_tx && serialized_tx_len) || serialized_tx_len > TREZOR_BITCOIN_SIGNED_TX_MAX_LEN || !output
        || !written || (request_type != TREZOR_BITCOIN_REQUEST_TXMETA
                           && request_type != TREZOR_BITCOIN_REQUEST_TXFINISHED)) {
        return false;
    }

    uint8_t* const serialized = malloc(TREZOR_BITCOIN_SIGNED_TX_MAX_LEN + TREZOR_BITCOIN_SIGNATURE_MAX_LEN + 16U);
    if (!serialized) {
        return false;
    }
    trezor_protobuf_writer_t serialized_writer;
    trezor_protobuf_writer_init(
        &serialized_writer, serialized, TREZOR_BITCOIN_SIGNED_TX_MAX_LEN + TREZOR_BITCOIN_SIGNATURE_MAX_LEN + 16U);
    if (!trezor_protobuf_write_varint_field(&serialized_writer, 1, signature_index)
        || !trezor_protobuf_write_bytes_field(&serialized_writer, 2, signature, signature_len)
        || (serialized_tx_len
            && !trezor_protobuf_write_bytes_field(&serialized_writer, 3, serialized_tx, serialized_tx_len))) {
        wally_bzero(serialized, TREZOR_BITCOIN_SIGNED_TX_MAX_LEN + TREZOR_BITCOIN_SIGNATURE_MAX_LEN + 16U);
        free(serialized);
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    const bool ok = trezor_protobuf_write_varint_field(&writer, 1, request_type)
        && (request_type == TREZOR_BITCOIN_REQUEST_TXFINISHED
            || trezor_protobuf_write_bytes_field(&writer, 2, NULL, 0))
        && trezor_protobuf_write_bytes_field(&writer, 3, serialized, serialized_writer.len);
    wally_bzero(serialized, TREZOR_BITCOIN_SIGNED_TX_MAX_LEN + TREZOR_BITCOIN_SIGNATURE_MAX_LEN + 16U);
    free(serialized);
    if (!ok) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

bool trezor_bitcoin_tx_request_encode_signed(const trezor_bitcoin_signing_state_t* const state,
    const uint8_t* const signature, const size_t signature_len, const uint8_t* const serialized_tx,
    const size_t serialized_tx_len, uint8_t* const output, const size_t output_len, size_t* const written)
{
    (void)state;
    return trezor_bitcoin_tx_request_encode_signed_part(TREZOR_BITCOIN_REQUEST_TXFINISHED, 0, signature,
        signature_len, serialized_tx, serialized_tx_len, output, output_len, written);
}

bool trezor_bitcoin_signed_tx_encode_next(
    trezor_bitcoin_signed_tx_t* const signed_tx, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!signed_tx || !output || !written || signed_tx->signatures_len == 0
        || signed_tx->signatures_len > TREZOR_BITCOIN_TX_INPUTS_MAX
        || signed_tx->next_signature_index >= signed_tx->signatures_len) {
        return false;
    }

    const size_t index = signed_tx->next_signature_index;
    const bool final_signature = index + 1U == signed_tx->signatures_len;
    const trezor_bitcoin_signature_t* const signature = &signed_tx->signatures[index];
    const bool ok = trezor_bitcoin_tx_request_encode_signed_part(final_signature ? TREZOR_BITCOIN_REQUEST_TXFINISHED
                                                                                 : TREZOR_BITCOIN_REQUEST_TXMETA,
        (uint32_t)index, signature->bytes, signature->len, final_signature ? signed_tx->serialized_tx : NULL,
        final_signature ? signed_tx->serialized_tx_len : 0, output, output_len, written);
    if (ok) {
        ++signed_tx->next_signature_index;
    }
    return ok;
}
#endif /* AMALGAMATED_BUILD */
