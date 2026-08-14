#ifndef AMALGAMATED_BUILD
#include "public_key.h"

#include "../../chains/bitcoin/path.h"
#include "../../chains/path.h"
#include "protobuf.h"

#include <string.h>
#include <wally_crypto.h>

static bool trezor_public_key_bool_value(const uint8_t* const value, const size_t value_len, bool* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > 1) {
        return false;
    }
    *output = raw != 0;
    return true;
}

static bool trezor_public_key_decode_path_part(
    trezor_public_key_request_t* const output, const uint8_t* const value, const size_t value_len)
{
    uint64_t path_part = 0;
    if (!output || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
        || !trezor_protobuf_read_varint_value(value, value_len, &path_part) || path_part > UINT32_MAX) {
        return false;
    }
    output->address_n[output->address_n_len++] = (uint32_t)path_part;
    return true;
}

static bool trezor_public_key_decode_common(const uint8_t* const payload, const size_t payload_len,
    trezor_public_key_request_t* const output, const trezor_public_key_request_kind_t kind)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    output->kind = kind;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (payload_len && reader.len == 0) {
        return false;
    }

    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_public_key_decode_path_part(output, value, value_len)) {
                return false;
            }
        } else if (field_number == 2 && kind == TREZOR_PUBLIC_KEY_REQUEST_ETHEREUM) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_public_key_bool_value(value, value_len, &output->show_display)) {
                return false;
            }
            output->has_show_display = true;
        } else if (field_number == 2 && kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || (value_len != 0 && memcmp(value, "secp256k1", value_len) != 0)) {
                return false;
            }
        } else if (field_number == 3 && kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_public_key_bool_value(value, value_len, &output->show_display)) {
                return false;
            }
            output->has_show_display = true;
        } else if (field_number == 4 && kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
            const bool allowed_coin = value_len == 0 || (value_len == 3 && memcmp(value, "ETH", value_len) == 0)
                || (value_len == 7 && memcmp(value, "Bitcoin", value_len) == 0)
                || (value_len == 7 && memcmp(value, "Testnet", value_len) == 0)
                || (value_len == 8 && memcmp(value, "Ethereum", value_len) == 0);
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || !allowed_coin
                || value_len >= sizeof(output->coin_name)) {
                return false;
            }
            if (value_len) {
                memcpy(output->coin_name, value, value_len);
                output->coin_name[value_len] = '\0';
                output->has_coin_name = true;
            }
        } else if (field_number == 5 && kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
            uint64_t script_type = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &script_type)
                || (script_type != BITCOIN_P2PKH_SPENDADDRESS && script_type != BITCOIN_P2WPKH_SPENDWITNESS
                    && script_type != BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)) {
                return false;
            }
            output->script_type = (uint32_t)script_type;
            output->has_script_type = true;
        } else if (field_number == 6 && kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_public_key_bool_value(value, value_len, &output->ignore_xpub_magic)) {
                return false;
            }
            output->has_ignore_xpub_magic = true;
        }
    }

    return output->address_n_len > 0;
}

bool trezor_public_key_decode_generic(
    const uint8_t* const payload, const size_t payload_len, trezor_public_key_request_t* const output)
{
    return trezor_public_key_decode_common(payload, payload_len, output, TREZOR_PUBLIC_KEY_REQUEST_GENERIC);
}

bool trezor_public_key_decode_ethereum(
    const uint8_t* const payload, const size_t payload_len, trezor_public_key_request_t* const output)
{
    return trezor_public_key_decode_common(payload, payload_len, output, TREZOR_PUBLIC_KEY_REQUEST_ETHEREUM);
}

bool trezor_public_key_is_root_fingerprint_probe(const trezor_public_key_request_t* const request)
{
    return request && request->kind == TREZOR_PUBLIC_KEY_REQUEST_GENERIC && request->address_n_len == 1
        && request->address_n[0] == chain_path_harden(0) && (!request->has_show_display || !request->show_display);
}

static bool trezor_public_key_encode_node(
    const trezor_public_key_response_t* const response, uint8_t* const output, const size_t output_len, size_t* written)
{
    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!response || !written
        || !trezor_protobuf_write_varint_field(&writer, 1, response->depth)
        || !trezor_protobuf_write_varint_field(&writer, 2, response->fingerprint)
        || !trezor_protobuf_write_varint_field(&writer, 3, response->child_num)
        || !trezor_protobuf_write_bytes_field(
               &writer, 4, response->chain_code, sizeof(response->chain_code))
        || !trezor_protobuf_write_bytes_field(
               &writer, 6, response->public_key, sizeof(response->public_key))) {
        return false;
    }

    *written = writer.len;
    return true;
}

static bool trezor_public_key_encode(
    const trezor_public_key_response_t* const response, uint8_t* const output, const size_t output_len,
    size_t* const written, const bool include_root_fingerprint)
{
    if (!response || !output || !written || response->xpub[0] == '\0') {
        return false;
    }

    uint8_t node_payload[128];
    size_t node_payload_len = 0;
    if (!trezor_public_key_encode_node(response, node_payload, sizeof(node_payload), &node_payload_len)) {
        wally_bzero(node_payload, sizeof(node_payload));
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    bool ok = trezor_protobuf_write_bytes_field(&writer, 1, node_payload, node_payload_len)
        && trezor_protobuf_write_string_field(&writer, 2, response->xpub);
    if (ok && include_root_fingerprint && response->has_root_fingerprint) {
        ok = trezor_protobuf_write_varint_field(&writer, 3, response->root_fingerprint);
    }

    wally_bzero(node_payload, sizeof(node_payload));
    if (!ok) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

bool trezor_public_key_encode_generic(const trezor_public_key_response_t* const response, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    return trezor_public_key_encode(response, output, output_len, written, true);
}

bool trezor_public_key_encode_ethereum(const trezor_public_key_response_t* const response, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    return trezor_public_key_encode(response, output, output_len, written, false);
}
#endif /* AMALGAMATED_BUILD */
