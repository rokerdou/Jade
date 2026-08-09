#ifndef AMALGAMATED_BUILD
#include "protocol.h"

#include "../messages.h"
#include "../protobuf.h"

#include <string.h>
#include <wally_crypto.h>

static bool trezor_ethereum_bool_value(const uint8_t* const value, const size_t value_len, bool* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > 1) {
        return false;
    }
    *output = raw != 0;
    return true;
}

bool trezor_ethereum_get_address_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_ethereum_get_address_t* const output)
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
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_ethereum_bool_value(value, value_len, &output->show_display)) {
                return false;
            }
            output->has_show_display = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len != 0) {
                return false;
            }
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_ethereum_bool_value(value, value_len, &output->chunkify)) {
                return false;
            }
            output->has_chunkify = true;
        }
    }

    return output->address_n_len > 0;
}

bool trezor_ethereum_address_encode(
    const char* const address, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!address || !output || !written) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_string_field(&writer, 2, address)) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}

static bool trezor_ethereum_u64_from_big_endian(
    const uint8_t* const bytes, const size_t bytes_len, uint64_t* const output)
{
    if (!output || (!bytes && bytes_len) || bytes_len > sizeof(uint64_t)) {
        return false;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < bytes_len; ++i) {
        value = (value << 8) | bytes[i];
    }
    *output = value;
    return true;
}

static bool trezor_ethereum_copy_value(
    uint8_t output[EVM_ABI_WORD_LEN], size_t* const output_len, const uint8_t* const value, const size_t value_len)
{
    if (!output || !output_len || (!value && value_len) || value_len > EVM_ABI_WORD_LEN
        || (value_len && value[0] == 0)) {
        return false;
    }

    wally_bzero(output, EVM_ABI_WORD_LEN);
    if (value_len) {
        memcpy(output, value, value_len);
    }
    *output_len = value_len;
    return true;
}

static bool trezor_ethereum_hex_nibble(const uint8_t c, uint8_t* const output)
{
    if (!output) {
        return false;
    }
    if (c >= '0' && c <= '9') {
        *output = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *output = (uint8_t)(10 + c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *output = (uint8_t)(10 + c - 'A');
        return true;
    }
    return false;
}

static bool trezor_ethereum_address_from_string(
    const uint8_t* const value, const size_t value_len, uint8_t output[ETHEREUM_ADDRESS_LEN], bool* const has_to)
{
    if (!output || !has_to || (!value && value_len)) {
        return false;
    }
    *has_to = false;
    wally_bzero(output, ETHEREUM_ADDRESS_LEN);
    if (value_len == 0) {
        return true;
    }

    size_t offset = 0;
    if (value_len == 42 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        offset = 2;
    } else if (value_len != 40) {
        return false;
    }
    if (value_len - offset != ETHEREUM_ADDRESS_LEN * 2) {
        return false;
    }

    for (size_t i = 0; i < ETHEREUM_ADDRESS_LEN; ++i) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!trezor_ethereum_hex_nibble(value[offset + (2 * i)], &high)
            || !trezor_ethereum_hex_nibble(value[offset + (2 * i) + 1], &low)) {
            wally_bzero(output, ETHEREUM_ADDRESS_LEN);
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    *has_to = true;
    return true;
}

static bool trezor_ethereum_apply_definitions(
    trezor_ethereum_signing_state_t* const state, const uint8_t* const value, const size_t value_len)
{
    if (!state || (!value && value_len)) {
        return false;
    }

    trezor_ethereum_definitions_t definitions;
    if (!trezor_ethereum_definitions_decode(value, value_len, &definitions)) {
        return false;
    }
    if (definitions.has_network && state->definitions.has_network) {
        wally_bzero(&definitions, sizeof(definitions));
        return false;
    }
    if (definitions.has_token && state->definitions.has_token) {
        wally_bzero(&definitions, sizeof(definitions));
        return false;
    }
    if (definitions.has_network) {
        state->definitions.has_network = true;
        state->definitions.network_chain_id = definitions.network_chain_id;
    }
    if (definitions.has_token) {
        state->definitions.has_token = true;
        memcpy(&state->definitions.token, &definitions.token, sizeof(state->definitions.token));
    }
    wally_bzero(&definitions, sizeof(definitions));
    return true;
}

static bool trezor_ethereum_set_next_chunk(trezor_ethereum_signing_state_t* const state)
{
    if (!state || state->data_received > state->data_len) {
        return false;
    }
    const size_t left = state->data_len - state->data_received;
    state->next_chunk_len = left > TREZOR_ETHEREUM_MAX_TX_CHUNK_LEN ? TREZOR_ETHEREUM_MAX_TX_CHUNK_LEN : left;
    return true;
}

static bool trezor_ethereum_sign_tx_decode_legacy(trezor_ethereum_signing_state_t* const state,
    const uint8_t* const payload, const size_t payload_len)
{
    bool has_gas_price = false;
    bool has_gas_limit = false;
    bool has_chain_id = false;
    size_t data_total = 0;
    bool saw_unsupported = false;

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
        uint64_t raw = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || state->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > UINT32_MAX) {
                return false;
            }
            state->address_n[state->address_n_len++] = (uint32_t)raw;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->nonce)) {
                return false;
            }
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->gas_price)) {
                return false;
            }
            has_gas_price = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->gas_limit)) {
                return false;
            }
            has_gas_limit = true;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_copy_value(state->value, &state->value_len, value, value_len)) {
                return false;
            }
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len > sizeof(state->data)) {
                return false;
            }
            if (value_len) {
                memcpy(state->data, value, value_len);
            }
            state->data_received = value_len;
        } else if (field_number == 8) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &raw)
                || raw > ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN) {
                return false;
            }
            data_total = (size_t)raw;
        } else if (field_number == 9) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &state->chain_id)) {
                return false;
            }
            has_chain_id = true;
        } else if (field_number == 10) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw != 0) {
                return false;
            }
        } else if (field_number == 11) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_address_from_string(value, value_len, state->to, &state->has_to)) {
                return false;
            }
        } else if (field_number == 12) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || !trezor_ethereum_apply_definitions(state, value, value_len)) {
                saw_unsupported = true;
            }
        } else if (field_number == 14) {
            saw_unsupported = true;
        } else if (field_number == 13) {
            bool chunkify = false;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_ethereum_bool_value(value, value_len, &chunkify)) {
                return false;
            }
        }
    }

    state->data_len = data_total;
    return !saw_unsupported && has_gas_price && has_gas_limit && has_chain_id && state->address_n_len > 0
        && state->has_to && state->data_received <= state->data_len
        && (state->data_len == 0 || state->data_received > 0) && trezor_ethereum_set_next_chunk(state);
}

static bool trezor_ethereum_sign_tx_decode_eip1559(trezor_ethereum_signing_state_t* const state,
    const uint8_t* const payload, const size_t payload_len)
{
    bool has_nonce = false;
    bool has_max_gas_fee = false;
    bool has_max_priority_fee = false;
    bool has_gas_limit = false;
    bool has_value = false;
    bool has_data_length = false;
    bool has_chain_id = false;
    bool saw_unsupported = false;

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
        uint64_t raw = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || state->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > UINT32_MAX) {
                return false;
            }
            state->address_n[state->address_n_len++] = (uint32_t)raw;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->nonce)) {
                return false;
            }
            has_nonce = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->max_fee_per_gas)) {
                return false;
            }
            has_max_gas_fee = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->max_priority_fee_per_gas)) {
                return false;
            }
            has_max_priority_fee = true;
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_u64_from_big_endian(value, value_len, &state->gas_limit)) {
                return false;
            }
            has_gas_limit = true;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_address_from_string(value, value_len, state->to, &state->has_to)) {
                return false;
            }
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_ethereum_copy_value(state->value, &state->value_len, value, value_len)) {
                return false;
            }
            has_value = true;
        } else if (field_number == 8) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len > sizeof(state->data)) {
                return false;
            }
            if (value_len) {
                memcpy(state->data, value, value_len);
            }
            state->data_received = value_len;
        } else if (field_number == 9) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &raw)
                || raw > ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN) {
                return false;
            }
            state->data_len = (size_t)raw;
            has_data_length = true;
        } else if (field_number == 10) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &state->chain_id)) {
                return false;
            }
            has_chain_id = true;
        } else if (field_number == 11 || field_number == 14) {
            saw_unsupported = true;
        } else if (field_number == 12) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || !trezor_ethereum_apply_definitions(state, value, value_len)) {
                saw_unsupported = true;
            }
        } else if (field_number == 13) {
            bool chunkify = false;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_ethereum_bool_value(value, value_len, &chunkify)) {
                return false;
            }
        }
    }

    return !saw_unsupported && has_nonce && has_max_gas_fee && has_max_priority_fee && has_gas_limit && has_value
        && has_data_length && has_chain_id && state->address_n_len > 0 && state->has_to
        && state->data_received <= state->data_len && (state->data_len == 0 || state->data_received > 0)
        && trezor_ethereum_set_next_chunk(state);
}

bool trezor_ethereum_sign_tx_init(trezor_ethereum_signing_state_t* const state, const uint16_t message_type,
    const uint8_t* const payload, const size_t payload_len)
{
    if (!state || (!payload && payload_len)) {
        return false;
    }

    wally_bzero(state, sizeof(*state));
    state->tx_type = message_type == TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559 ? ETHEREUM_TX_TYPE_EIP1559
                                                                         : ETHEREUM_TX_TYPE_LEGACY;
    const bool ok = message_type == TREZOR_MSG_ETHEREUM_SIGN_TX
        ? trezor_ethereum_sign_tx_decode_legacy(state, payload, payload_len)
        : message_type == TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559
        ? trezor_ethereum_sign_tx_decode_eip1559(state, payload, payload_len)
        : false;
    if (!ok) {
        wally_bzero(state, sizeof(*state));
    }
    return ok;
}

bool trezor_ethereum_tx_ack_apply(
    trezor_ethereum_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state || state->next_chunk_len == 0 || (!payload && payload_len)) {
        return false;
    }

    const uint8_t* chunk = NULL;
    size_t chunk_len = 0;
    bool saw_chunk = false;

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
        if (field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_LEN || saw_chunk) {
            return false;
        }
        chunk = value;
        chunk_len = value_len;
        saw_chunk = true;
    }

    if (!saw_chunk || chunk_len != state->next_chunk_len || chunk_len > sizeof(state->data) - state->data_received) {
        return false;
    }
    memcpy(state->data + state->data_received, chunk, chunk_len);
    state->data_received += chunk_len;
    return trezor_ethereum_set_next_chunk(state);
}

bool trezor_ethereum_signing_state_ready(const trezor_ethereum_signing_state_t* const state)
{
    return state && state->data_received == state->data_len && state->next_chunk_len == 0;
}

bool trezor_ethereum_tx_request_encode_data(
    const size_t data_length, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || data_length == 0 || data_length > TREZOR_ETHEREUM_MAX_TX_CHUNK_LEN) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_varint_field(&writer, 1, data_length)) {
        wally_bzero(output, output_len);
        return false;
    }
    *written = writer.len;
    return true;
}

bool trezor_ethereum_tx_request_encode_signature(const ethereum_signature_t* const signature, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!signature || !output || !written || signature->v > UINT32_MAX) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_varint_field(&writer, 2, signature->v)
        || !trezor_protobuf_write_bytes_field(&writer, 3, signature->r, sizeof(signature->r))
        || !trezor_protobuf_write_bytes_field(&writer, 4, signature->s, sizeof(signature->s))) {
        wally_bzero(output, output_len);
        return false;
    }
    *written = writer.len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
