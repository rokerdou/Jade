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

static bool trezor_bitcoin_uint32_value(const uint8_t* const value, const size_t value_len, uint32_t* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > UINT32_MAX) {
        return false;
    }
    *output = (uint32_t)raw;
    return true;
}

static bool trezor_bitcoin_uint64_value(const uint8_t* const value, const size_t value_len, uint64_t* const output)
{
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, output)) {
        return false;
    }
    return true;
}

static bool trezor_bitcoin_read_coin_name(
    const uint8_t* const value, const size_t value_len, char* const output, const size_t output_len)
{
    if (!value || !output || output_len == 0 || value_len == 0 || value_len >= output_len) {
        return false;
    }
    memcpy(output, value, value_len);
    output[value_len] = '\0';
    return strcmp(output, "Testnet") == 0;
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

bool trezor_bitcoin_sign_tx_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_sign_tx_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    output->version = 1;
    output->lock_time = 0;
    output->serialize = true;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (payload_len && reader.len == 0) {
        return false;
    }

    bool has_inputs_count = false;
    bool has_outputs_count = false;
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
                || !trezor_bitcoin_uint32_value(value, value_len, &output->outputs_count)) {
                return false;
            }
            has_outputs_count = true;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->inputs_count)) {
                return false;
            }
            has_inputs_count = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !trezor_bitcoin_read_coin_name(
                    value, value_len, output->coin_name, sizeof(output->coin_name))) {
                return false;
            }
            output->has_coin_name = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->version)) {
                return false;
            }
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->lock_time)) {
                return false;
            }
        } else if (field_number == 11) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->amount_unit)) {
                return false;
            }
            output->has_amount_unit = true;
        } else if (field_number == 12) {
            bool decred_staking_ticket = false;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &decred_staking_ticket) || decred_staking_ticket) {
                return false;
            }
        } else if (field_number == 13) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &output->serialize)) {
                return false;
            }
        } else if (field_number == 15) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_bool_value(value, value_len, &output->chunkify)) {
                return false;
            }
            output->has_chunkify = true;
        } else {
            return false;
        }
    }

    return has_inputs_count && has_outputs_count && output->inputs_count > 0
        && output->inputs_count <= TREZOR_BITCOIN_TX_INPUTS_MAX && output->outputs_count > 0
        && output->outputs_count <= TREZOR_BITCOIN_TX_OUTPUTS_MAX
        && (!output->has_amount_unit || output->amount_unit == 0);
}

static bool trezor_bitcoin_tx_input_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_tx_input_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    output->sequence = UINT32_MAX;
    output->script_type = BITCOIN_P2PKH_SPENDADDRESS;

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
            uint32_t path_part = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !trezor_bitcoin_uint32_value(value, value_len, &path_part)) {
                return false;
            }
            output->address_n[output->address_n_len++] = path_part;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len != sizeof(output->prev_hash)) {
                return false;
            }
            memcpy(output->prev_hash, value, value_len);
            output->has_prev_hash = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->prev_index)) {
                return false;
            }
            output->has_prev_index = true;
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->sequence)) {
                return false;
            }
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->script_type)) {
                return false;
            }
        } else if (field_number == 8) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint64_value(value, value_len, &output->amount)) {
                return false;
            }
            output->has_amount = true;
        } else {
            return false;
        }
    }

    const bool supported_script = output->script_type == BITCOIN_P2PKH_SPENDADDRESS
        || output->script_type == BITCOIN_P2WPKH_SPENDWITNESS
        || output->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
    return output->address_n_len > 0 && output->has_prev_hash && output->has_prev_index && output->has_amount
        && supported_script;
}

static bool trezor_bitcoin_tx_output_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_tx_output_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    output->script_type = 0;

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
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len == 0 || value_len >= sizeof(output->address)) {
                return false;
            }
            memcpy(output->address, value, value_len);
            output->address[value_len] = '\0';
            output->has_address = true;
        } else if (field_number == 2) {
            uint32_t path_part = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !trezor_bitcoin_uint32_value(value, value_len, &path_part)) {
                return false;
            }
            output->address_n[output->address_n_len++] = path_part;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint64_value(value, value_len, &output->amount)) {
                return false;
            }
            output->has_amount = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->script_type)) {
                return false;
            }
        } else {
            return false;
        }
    }

    return output->has_amount && output->script_type == 0
        && ((output->has_address && output->address_n_len == 0) || (!output->has_address && output->address_n_len > 0));
}

static bool trezor_bitcoin_transaction_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_transaction_t* const output)
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
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->version)) {
                return false;
            }
            output->has_version = true;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->inputs_len >= TREZOR_BITCOIN_TX_INPUTS_MAX
                || !trezor_bitcoin_tx_input_decode(value, value_len, &output->inputs[output->inputs_len])) {
                return false;
            }
            ++output->inputs_len;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->lock_time)) {
                return false;
            }
            output->has_lock_time = true;
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->outputs_len >= TREZOR_BITCOIN_TX_OUTPUTS_MAX
                || !trezor_bitcoin_tx_output_decode(value, value_len, &output->outputs[output->outputs_len])) {
                return false;
            }
            ++output->outputs_len;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->inputs_cnt)) {
                return false;
            }
            output->has_inputs_cnt = true;
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->outputs_cnt)) {
                return false;
            }
            output->has_outputs_cnt = true;
        } else {
            return false;
        }
    }

    return (output->inputs_len > 0 || output->outputs_len > 0 || output->has_inputs_cnt || output->has_outputs_cnt
        || output->has_version || output->has_lock_time);
}

bool trezor_bitcoin_tx_ack_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_transaction_t* const output)
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

    bool has_tx = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_tx
            || !trezor_bitcoin_transaction_decode(value, value_len, output)) {
            return false;
        }
        has_tx = true;
    }
    return has_tx;
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

bool trezor_bitcoin_tx_request_encode(const trezor_bitcoin_request_type_t request_type, const bool has_request_index,
    const uint32_t request_index, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || request_type > TREZOR_BITCOIN_REQUEST_TXPAYMENTREQ) {
        return false;
    }

    const bool write_details = request_type != TREZOR_BITCOIN_REQUEST_TXFINISHED;
    uint8_t details[16];
    trezor_protobuf_writer_t details_writer;
    trezor_protobuf_writer_init(&details_writer, details, sizeof(details));
    if (has_request_index && !trezor_protobuf_write_varint_field(&details_writer, 1, request_index)) {
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

bool trezor_bitcoin_signing_init(
    trezor_bitcoin_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state) {
        return false;
    }

    wally_bzero(state, sizeof(*state));
    if (!trezor_bitcoin_sign_tx_decode(payload, payload_len, &state->request)) {
        return false;
    }
    state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META;
    return true;
}

static bool trezor_bitcoin_add_u64(uint64_t* const total, const uint64_t value)
{
    if (!total || value > UINT64_MAX - *total) {
        return false;
    }
    *total += value;
    return true;
}

static bool trezor_bitcoin_signing_validate_totals(trezor_bitcoin_signing_state_t* const state)
{
    if (!state || state->inputs_len != state->request.inputs_count || state->outputs_len != state->request.outputs_count) {
        return false;
    }

    state->total_input = 0;
    state->total_output = 0;
    for (size_t i = 0; i < state->inputs_len; ++i) {
        if (!state->inputs[i].has_amount || !trezor_bitcoin_add_u64(&state->total_input, state->inputs[i].amount)) {
            return false;
        }
    }
    for (size_t i = 0; i < state->outputs_len; ++i) {
        if (!state->outputs[i].has_amount || !trezor_bitcoin_add_u64(&state->total_output, state->outputs[i].amount)) {
            return false;
        }
    }
    if (state->total_output > state->total_input) {
        return false;
    }
    state->fee = state->total_input - state->total_output;
    return true;
}

bool trezor_bitcoin_signing_apply_tx_ack(
    trezor_bitcoin_signing_state_t* const state, const uint8_t* const payload, const size_t payload_len)
{
    if (!state || state->phase == TREZOR_BITCOIN_SIGNING_PHASE_NONE
        || state->phase == TREZOR_BITCOIN_SIGNING_PHASE_READY) {
        return false;
    }

    trezor_bitcoin_transaction_t tx_ack;
    if (!trezor_bitcoin_tx_ack_decode(payload, payload_len, &tx_ack)) {
        return false;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META) {
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 0 || !tx_ack.has_inputs_cnt || !tx_ack.has_outputs_cnt
            || tx_ack.inputs_cnt != state->request.inputs_count || tx_ack.outputs_cnt != state->request.outputs_count
            || (tx_ack.has_version && tx_ack.version != state->request.version)
            || (tx_ack.has_lock_time && tx_ack.lock_time != state->request.lock_time)) {
            return false;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT) {
        if (tx_ack.inputs_len != 1 || tx_ack.outputs_len != 0 || state->inputs_len >= state->request.inputs_count) {
            return false;
        }
        state->inputs[state->inputs_len++] = tx_ack.inputs[0];
        if (state->inputs_len < state->request.inputs_count) {
            return true;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT;
        return true;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT) {
        if (tx_ack.inputs_len != 0 || tx_ack.outputs_len != 1 || state->outputs_len >= state->request.outputs_count) {
            return false;
        }
        state->outputs[state->outputs_len++] = tx_ack.outputs[0];
        if (state->outputs_len < state->request.outputs_count) {
            return true;
        }
        if (!trezor_bitcoin_signing_validate_totals(state)) {
            return false;
        }
        state->phase = TREZOR_BITCOIN_SIGNING_PHASE_READY;
        return true;
    }

    return false;
}

bool trezor_bitcoin_signing_encode_next_request(const trezor_bitcoin_signing_state_t* const state, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!state || !output || !written) {
        return false;
    }

    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_META) {
        return trezor_bitcoin_tx_request_encode(
            TREZOR_BITCOIN_REQUEST_TXMETA, false, 0, output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_INPUT) {
        if (state->inputs_len >= state->request.inputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXINPUT, true, (uint32_t)state->inputs_len,
            output, output_len, written);
    }
    if (state->phase == TREZOR_BITCOIN_SIGNING_PHASE_EXPECT_OUTPUT) {
        if (state->outputs_len >= state->request.outputs_count) {
            return false;
        }
        return trezor_bitcoin_tx_request_encode(TREZOR_BITCOIN_REQUEST_TXOUTPUT, true, (uint32_t)state->outputs_len,
            output, output_len, written);
    }
    return false;
}

bool trezor_bitcoin_signing_ready(const trezor_bitcoin_signing_state_t* const state)
{
    return state && state->phase == TREZOR_BITCOIN_SIGNING_PHASE_READY;
}
#endif /* AMALGAMATED_BUILD */
