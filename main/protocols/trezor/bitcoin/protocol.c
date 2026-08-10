#ifndef AMALGAMATED_BUILD
#include "protocol.h"

#include "policy.h"
#include "requests.h"
#include "../protobuf.h"
#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_address.h>
#include <wally_map.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <wally_crypto.h>

#define TREZOR_BITCOIN_SIGHASH_ALL 1U

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
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    return trezor_bitcoin_coin_from_name(output, &coin);
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
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    return output->address_n_len > 0
        && (!output->has_coin_name || trezor_bitcoin_coin_from_name(output->coin_name, &coin)) && supported_script;
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

    return has_inputs_count && has_outputs_count && output->has_coin_name && output->inputs_count > 0
        && output->inputs_count <= TREZOR_BITCOIN_TX_INPUTS_MAX && output->outputs_count > 0
        && output->outputs_count <= TREZOR_BITCOIN_TX_OUTPUTS_MAX
        && (!output->has_amount_unit || output->amount_unit == 0) && (output->version == 1 || output->version == 2)
        && output->lock_time == 0 && output->serialize;
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
        } else if (field_number == 20) {
            uint32_t coinjoin_flags = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &coinjoin_flags) || coinjoin_flags != 0) {
                return false;
            }
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
        } else if (field_number == 9) {
            uint32_t extra_data_len = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &extra_data_len) || extra_data_len != 0) {
                return false;
            }
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

bool trezor_bitcoin_prev_input_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_prev_input_t* const output)
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

        if (field_number == 2) {
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
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len > sizeof(output->script_sig)) {
                return false;
            }
            memcpy(output->script_sig, value, value_len);
            output->script_sig_len = value_len;
            output->has_script_sig = true;
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &output->sequence)) {
                return false;
            }
            output->has_sequence = true;
        } else {
            return false;
        }
    }

    return output->has_prev_hash && output->has_prev_index && output->has_script_sig && output->has_sequence;
}

bool trezor_bitcoin_prev_output_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_prev_output_t* const output)
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
                || !trezor_bitcoin_uint64_value(value, value_len, &output->amount)) {
                return false;
            }
            output->has_amount = true;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len == 0 || value_len > sizeof(output->script_pubkey)) {
                return false;
            }
            memcpy(output->script_pubkey, value, value_len);
            output->script_pubkey_len = value_len;
            output->has_script_pubkey = true;
        } else {
            return false;
        }
    }

    return output->has_amount && output->has_script_pubkey;
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
        if (!trezor_bitcoin_policy_calculate_totals(state)
            || !trezor_bitcoin_policy_estimate_p2wpkh_fee_rate(state)) {
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

bool trezor_bitcoin_signing_to_confirm_request(
    const trezor_bitcoin_signing_state_t* const state, bitcoin_confirm_request_t* const request)
{
    if (!state || !request || !trezor_bitcoin_policy_is_p2wpkh_basic(state)
        || state->inputs[0].address_n_len > CHAIN_CONFIRM_MAX_PATH_LEN) {
        return false;
    }

    wally_bzero(request, sizeof(*request));
    request->path_len = state->inputs[0].address_n_len;
    memcpy(request->path, state->inputs[0].address_n, request->path_len * sizeof(request->path[0]));

    size_t external_outputs = 0;
    for (size_t i = 0; i < state->outputs_len; ++i) {
        const trezor_bitcoin_tx_output_t* const output = &state->outputs[i];
        if (output->has_address) {
            ++external_outputs;
            if (external_outputs == 1) {
                memcpy(request->to, output->address, strlen(output->address) + 1);
            }
            if (!trezor_bitcoin_add_u64(&request->amount, output->amount)) {
                wally_bzero(request, sizeof(*request));
                return false;
            }
        } else if (!trezor_bitcoin_add_u64(&request->change, output->amount)) {
            wally_bzero(request, sizeof(*request));
            return false;
        }
    }
    if (external_outputs != 1 || request->amount == 0 || request->to[0] == '\0') {
        wally_bzero(request, sizeof(*request));
        return false;
    }
    request->fee = state->fee;
    request->fee_rate_sats_per_vbyte = state->fee_rate_sats_per_vbyte;
    return true;
}

static bool trezor_bitcoin_path_from_input(const trezor_bitcoin_tx_input_t* const input, wallet_core_path_t* const path)
{
    if (!input || !path || input->address_n_len == 0 || input->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    wally_bzero(path, sizeof(*path));
    path->len = input->address_n_len;
    memcpy(path->parts, input->address_n, input->address_n_len * sizeof(input->address_n[0]));
    return true;
}

static bool trezor_bitcoin_output_script(const trezor_bitcoin_tx_output_t* const output,
    const trezor_bitcoin_coin_t coin, uint8_t* const script, const size_t script_len, size_t* const written)
{
    if (!output || !script || !written) {
        return false;
    }

    if (output->has_address) {
        return wally_addr_segwit_to_bytes(output->address, trezor_bitcoin_coin_segwit_hrp(coin), 0, script,
                   script_len, written)
            == WALLY_OK
            && *written > 0;
    }

    wallet_core_path_t path;
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    wally_bzero(&path, sizeof(path));
    wally_bzero(pubkey, sizeof(pubkey));
    if (output->address_n_len == 0 || output->address_n_len > WALLET_CORE_MAX_PATH_LEN) {
        return false;
    }
    path.len = output->address_n_len;
    memcpy(path.parts, output->address_n, output->address_n_len * sizeof(output->address_n[0]));
    const bool ok = wallet_core_get_public_key(&path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && wally_witness_program_from_bytes(pubkey, sizeof(pubkey), WALLY_SCRIPT_HASH160, script, script_len, written)
            == WALLY_OK
        && *written == WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    wally_bzero(&path, sizeof(path));
    wally_bzero(pubkey, sizeof(pubkey));
    return ok;
}

static bool trezor_bitcoin_add_unsigned_inputs(
    struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state)
{
    if (!tx || !state) {
        return false;
    }
    for (size_t i = 0; i < state->inputs_len; ++i) {
        const trezor_bitcoin_tx_input_t* const input = &state->inputs[i];
        if (wally_tx_add_raw_input(tx, input->prev_hash, sizeof(input->prev_hash), input->prev_index, input->sequence,
                NULL, 0, NULL, 0)
            != WALLY_OK) {
            return false;
        }
    }
    return true;
}

static bool trezor_bitcoin_add_outputs(
    struct wally_tx* const tx, const trezor_bitcoin_signing_state_t* const state, const trezor_bitcoin_coin_t coin)
{
    if (!tx || !state) {
        return false;
    }
    for (size_t i = 0; i < state->outputs_len; ++i) {
        uint8_t output_script[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
        size_t output_script_len = 0;
        wally_bzero(output_script, sizeof(output_script));
        const bool ok = trezor_bitcoin_output_script(
                            &state->outputs[i], coin, output_script, sizeof(output_script), &output_script_len)
            && wally_tx_add_raw_output(tx, state->outputs[i].amount, output_script, output_script_len, 0) == WALLY_OK;
        wally_bzero(output_script, sizeof(output_script));
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool trezor_bitcoin_signing_build_p2wpkh_hash(const trezor_bitcoin_signing_state_t* const state,
    const size_t input_index, wallet_core_path_t* const path, uint8_t* const digest, const size_t digest_len)
{
    if (!trezor_bitcoin_policy_is_p2wpkh_basic(state) || input_index >= state->inputs_len || !path || !digest
        || digest_len != SHA256_LEN) {
        return false;
    }

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    const trezor_bitcoin_tx_input_t* const input = &state->inputs[input_index];
    bool ok = false;
    struct wally_tx* tx = NULL;
    struct wally_map values;
    memset(&values, 0, sizeof(values));

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    uint8_t prevout_script[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    size_t prevout_script_len = 0;
    wally_bzero(pubkey, sizeof(pubkey));
    wally_bzero(prevout_script, sizeof(prevout_script));
    wally_bzero(digest, digest_len);

    wallet_core_path_t local_path;
    if (!trezor_bitcoin_policy_signing_coin(state, &coin) || !trezor_bitcoin_path_from_input(input, &local_path)) {
        goto cleanup;
    }

    ok = wallet_core_get_public_key(&local_path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && wally_witness_program_from_bytes(pubkey, sizeof(pubkey), WALLY_SCRIPT_HASH160, prevout_script,
               sizeof(prevout_script), &prevout_script_len)
            == WALLY_OK
        && prevout_script_len == sizeof(prevout_script);
    if (!ok) {
        goto cleanup;
    }

    ok = wally_tx_init_alloc(
             state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx && trezor_bitcoin_add_unsigned_inputs(tx, state) && trezor_bitcoin_add_outputs(tx, state, coin)
        && wally_map_init(state->inputs_len, NULL, &values) == WALLY_OK;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        ok = wally_map_add_integer(&values, (uint32_t)i, (const uint8_t*)&state->inputs[i].amount,
                 sizeof(state->inputs[i].amount))
            == WALLY_OK;
    }
    ok = ok
        && wally_tx_get_input_signature_hash(tx, input_index, NULL, NULL, &values, prevout_script, prevout_script_len, 0,
               WALLY_NO_CODESEPARATOR, NULL, 0, NULL, 0, TREZOR_BITCOIN_SIGHASH_ALL, WALLY_SIGTYPE_SW_V0, NULL,
               digest, digest_len)
            == WALLY_OK;
    if (ok) {
        *path = local_path;
    }

cleanup:
    if (tx) {
        wally_tx_free(tx);
    }
    wally_map_clear(&values);
    wally_bzero(&local_path, sizeof(local_path));
    wally_bzero(pubkey, sizeof(pubkey));
    wally_bzero(prevout_script, sizeof(prevout_script));
    if (!ok) {
        wally_bzero(digest, digest_len);
    }
    return ok;
}

bool trezor_bitcoin_signing_build_p2wpkh_signed_tx(const trezor_bitcoin_signing_state_t* const state,
    const trezor_bitcoin_signature_t* const signatures, const size_t signatures_len, uint8_t* const serialized_tx,
    const size_t serialized_tx_len, size_t* const serialized_tx_written)
{
    if (!trezor_bitcoin_policy_is_p2wpkh_basic(state) || !signatures || signatures_len != state->inputs_len
        || !serialized_tx || !serialized_tx_written) {
        return false;
    }

    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    bool ok = false;
    struct wally_tx* tx = NULL;
    struct wally_tx_witness_stack* witnesses[TREZOR_BITCOIN_TX_INPUTS_MAX];
    for (size_t i = 0; i < TREZOR_BITCOIN_TX_INPUTS_MAX; ++i) {
        witnesses[i] = NULL;
    }

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    wally_bzero(pubkey, sizeof(pubkey));
    *serialized_tx_written = 0;

    ok = trezor_bitcoin_policy_signing_coin(state, &coin)
        && wally_tx_init_alloc(
               state->request.version, state->request.lock_time, state->inputs_len, state->outputs_len, &tx)
            == WALLY_OK
        && tx;
    for (size_t i = 0; ok && i < state->inputs_len; ++i) {
        wallet_core_path_t path;
        wally_bzero(&path, sizeof(path));
        ok = signatures[i].len >= 2 && signatures[i].len <= TREZOR_BITCOIN_SIGNATURE_MAX_LEN
            && trezor_bitcoin_path_from_input(&state->inputs[i], &path)
            && wallet_core_get_public_key(&path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
            && wally_tx_witness_stack_init_alloc(2, &witnesses[i]) == WALLY_OK && witnesses[i]
            && wally_tx_witness_stack_add(witnesses[i], signatures[i].bytes, signatures[i].len) == WALLY_OK
            && wally_tx_witness_stack_add(witnesses[i], pubkey, sizeof(pubkey)) == WALLY_OK
            && wally_tx_add_raw_input(tx, state->inputs[i].prev_hash, sizeof(state->inputs[i].prev_hash),
                   state->inputs[i].prev_index, state->inputs[i].sequence, NULL, 0, witnesses[i], 0)
                == WALLY_OK;
        wally_bzero(&path, sizeof(path));
        wally_bzero(pubkey, sizeof(pubkey));
    }
    ok = ok && trezor_bitcoin_add_outputs(tx, state, coin)
        && wally_tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS, serialized_tx, serialized_tx_len, serialized_tx_written)
            == WALLY_OK;

    if (tx) {
        wally_tx_free(tx);
    }
    for (size_t i = 0; i < TREZOR_BITCOIN_TX_INPUTS_MAX; ++i) {
        if (witnesses[i]) {
            wally_tx_witness_stack_free(witnesses[i]);
        }
    }
    wally_bzero(pubkey, sizeof(pubkey));
    if (!ok) {
        wally_bzero(serialized_tx, serialized_tx_len);
        *serialized_tx_written = 0;
    }
    return ok;
}
#endif /* AMALGAMATED_BUILD */
