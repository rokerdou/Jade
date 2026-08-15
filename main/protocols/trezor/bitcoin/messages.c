#ifndef AMALGAMATED_BUILD
#include "messages.h"

#include "policy.h"
#include "../protobuf.h"
#include "../../../chains/bitcoin/path.h"

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
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    return trezor_bitcoin_coin_from_name(output, &coin);
}

static bool trezor_bitcoin_normalize_multisig_payload(const uint8_t* const payload, const size_t payload_len,
    const bool has_multisig, const uint32_t script_type, trezor_bitcoin_multisig_summary_t* const summary)
{
    if (!summary) {
        return false;
    }
    wally_bzero(summary, sizeof(*summary));
    if (!has_multisig) {
        return true;
    }
    if (!payload || payload_len == 0) {
        return false;
    }

    trezor_bitcoin_multisig_t multisig;
    trezor_bitcoin_multisig_policy_t policy;
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    const bool ok = trezor_bitcoin_multisig_decode(payload, payload_len, &multisig)
        && trezor_bitcoin_multisig_normalize(&multisig, script_type, &policy)
        && policy.num_pubkeys <= UINT8_MAX && policy.script_pubkey_len <= sizeof(summary->script_pubkey);
    if (ok) {
        summary->variant = policy.variant;
        summary->threshold = policy.threshold;
        summary->num_pubkeys = (uint8_t)policy.num_pubkeys;
        summary->sorted = policy.sorted;
        memcpy(summary->script_pubkey, policy.script_pubkey, policy.script_pubkey_len);
        summary->script_pubkey_len = policy.script_pubkey_len;
    }
    wally_bzero(&multisig, sizeof(multisig));
    wally_bzero(&policy, sizeof(policy));
    if (!ok) {
        wally_bzero(summary, sizeof(*summary));
    }
    return ok;
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

    const uint8_t* multisig_payload = NULL;
    size_t multisig_payload_len = 0;
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
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->has_multisig
                || value_len == 0) {
                return false;
            }
            multisig_payload = value;
            multisig_payload_len = value_len;
            output->has_multisig = true;
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

    const uint32_t script_type = output->has_script_type ? output->script_type : BITCOIN_P2PKH_SPENDADDRESS;
    const bool supported_script = output->has_multisig
        ? (script_type == BITCOIN_MULTISIG_SPENDMULTISIG || script_type == BITCOIN_P2WPKH_SPENDWITNESS
            || script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)
        : (script_type == BITCOIN_P2PKH_SPENDADDRESS || script_type == BITCOIN_P2WPKH_SPENDWITNESS
            || script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS);
    trezor_bitcoin_coin_t coin = TREZOR_BITCOIN_COIN_MAINNET;
    return output->address_n_len > 0
        && (!output->has_coin_name || trezor_bitcoin_coin_from_name(output->coin_name, &coin)) && supported_script
        && trezor_bitcoin_normalize_multisig_payload(
            multisig_payload, multisig_payload_len, output->has_multisig, script_type, &output->multisig);
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

    const uint8_t* multisig_payload = NULL;
    size_t multisig_payload_len = 0;
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
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->has_multisig
                || value_len == 0) {
                return false;
            }
            multisig_payload = value;
            multisig_payload_len = value_len;
            output->has_multisig = true;
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

    const bool supported_script = output->has_multisig
        ? (output->script_type == BITCOIN_MULTISIG_SPENDMULTISIG
            || output->script_type == BITCOIN_P2WPKH_SPENDWITNESS
            || output->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)
        : (output->script_type == BITCOIN_P2PKH_SPENDADDRESS
            || output->script_type == BITCOIN_P2WPKH_SPENDWITNESS
            || output->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS);
    return output->address_n_len > 0 && output->has_prev_hash && output->has_prev_index
        && (output->has_amount || output->script_type == BITCOIN_P2PKH_SPENDADDRESS
            || output->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)
        && supported_script && trezor_bitcoin_normalize_multisig_payload(multisig_payload, multisig_payload_len,
                                   output->has_multisig, output->script_type, &output->multisig);
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

    const uint8_t* multisig_payload = NULL;
    size_t multisig_payload_len = 0;
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
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->has_multisig
                || value_len == 0) {
                return false;
            }
            multisig_payload = value;
            multisig_payload_len = value_len;
            output->has_multisig = true;
        } else {
            return false;
        }
    }

    const bool address_source_ok = output->has_multisig
        ? (!output->has_address && output->address_n_len > 0 && output->script_type == BITCOIN_PAYTOMULTISIG)
        : ((output->has_address && output->address_n_len == 0) || (!output->has_address && output->address_n_len > 0));
    return output->has_amount && address_source_ok
        && trezor_bitcoin_normalize_multisig_payload(multisig_payload, multisig_payload_len, output->has_multisig,
            BITCOIN_MULTISIG_SPENDMULTISIG, &output->multisig);
}

bool trezor_bitcoin_prev_input_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_input_t* output);
bool trezor_bitcoin_prev_output_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_prev_output_t* output);

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

static bool trezor_bitcoin_transaction_prev_input_decode(
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

    bool has_input = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number != 2 || wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_input
            || !trezor_bitcoin_prev_input_decode(value, value_len, output)) {
            return false;
        }
        has_input = true;
    }
    return has_input;
}

static bool trezor_bitcoin_transaction_prev_output_decode(
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

    bool has_output = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }

        if (field_number != 3 || wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_output
            || !trezor_bitcoin_prev_output_decode(value, value_len, output)) {
            return false;
        }
        has_output = true;
    }
    return has_output;
}

bool trezor_bitcoin_tx_ack_prev_input_decode(
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
            || !trezor_bitcoin_transaction_prev_input_decode(value, value_len, output)) {
            return false;
        }
        has_tx = true;
    }
    return has_tx;
}

bool trezor_bitcoin_tx_ack_prev_output_decode(
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
            || !trezor_bitcoin_transaction_prev_output_decode(value, value_len, output)) {
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
        } else if (field_number == 6) {
            uint32_t script_type = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_bitcoin_uint32_value(value, value_len, &script_type)
                || script_type != BITCOIN_P2PKH_SPENDADDRESS) {
                return false;
            }
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
#endif /* AMALGAMATED_BUILD */
