#ifndef AMALGAMATED_BUILD
#include "bitcoin.h"

#include "protobuf.h"
#include "../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_crypto.h>

static bool trezor_bitcoin_bool_value(const uint8_t* const value, const size_t value_len, bool* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > 1) {
        return false;
    }
    *output = raw != 0;
    return true;
}

bool trezor_bitcoin_get_address_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_get_address_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
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
            uint64_t path_part = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !trezor_protobuf_read_varint_value(value, value_len, &path_part) || path_part > UINT32_MAX) {
                return false;
            }
            output->address_n[output->address_n_len++] = (uint32_t)path_part;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len == 0 || value_len >= sizeof(output->coin_name)) {
                return false;
            }
            memcpy(output->coin_name, value, value_len);
            output->coin_name[value_len] = '\0';
            output->has_coin_name = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &output->show_display)) {
                return false;
            }
            output->has_show_display = true;
        } else if (field_number == 4) {
            return false;
        } else if (field_number == 5) {
            uint64_t script_type = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &script_type) || script_type > UINT32_MAX) {
                return false;
            }
            output->script_type = (uint32_t)script_type;
            output->has_script_type = true;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &output->ignore_xpub_magic)) {
                return false;
            }
            output->has_ignore_xpub_magic = true;
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &output->chunkify)) {
                return false;
            }
            output->has_chunkify = true;
        }
    }

    const bool supported_script = !output->has_script_type || output->script_type == BITCOIN_P2PKH_SPENDADDRESS
        || output->script_type == BITCOIN_P2WPKH_SPENDWITNESS
        || output->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    return output->address_n_len > 0
        && (!output->has_coin_name || strcmp(output->coin_name, "Testnet") == 0) && supported_script;
}

bool trezor_bitcoin_address_encode(
    const char* const address, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!address || !output || !written) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_string_field(&writer, 1, address)) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
