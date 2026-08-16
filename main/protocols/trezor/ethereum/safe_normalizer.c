#ifndef AMALGAMATED_BUILD
#include "safe_normalizer.h"

#include "../protobuf.h"

#include <string.h>
#include <wally_crypto.h>

static bool trezor_safe_hex_nibble(const uint8_t c, uint8_t* const output)
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

static bool trezor_safe_address_from_string(
    const uint8_t* const value, const size_t value_len, uint8_t output[ETHEREUM_ADDRESS_LEN])
{
    if (!value || !output) {
        return false;
    }

    size_t offset = 0;
    if (value_len == 42 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        offset = 2;
    } else if (value_len != 40) {
        return false;
    }
    if (value_len - offset != ETHEREUM_ADDRESS_LEN * 2U) {
        return false;
    }

    for (size_t i = 0; i < ETHEREUM_ADDRESS_LEN; ++i) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!trezor_safe_hex_nibble(value[offset + (2U * i)], &high)
            || !trezor_safe_hex_nibble(value[offset + (2U * i) + 1U], &low)) {
            wally_bzero(output, ETHEREUM_ADDRESS_LEN);
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool trezor_safe_copy_u256(
    uint8_t output[EVM_ABI_WORD_LEN], const uint8_t* const value, const size_t value_len)
{
    if (!output || (!value && value_len) || value_len > EVM_ABI_WORD_LEN || (value_len > 1U && value[0] == 0)) {
        return false;
    }

    wally_bzero(output, EVM_ABI_WORD_LEN);
    if (value_len) {
        memcpy(output + EVM_ABI_WORD_LEN - value_len, value, value_len);
    }
    return true;
}

bool trezor_ethereum_safe_tx_request_encode(
    uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written) {
        return false;
    }
    if (output_len) {
        wally_bzero(output, output_len);
    }
    *written = 0;
    return true;
}

bool trezor_ethereum_safe_tx_ack_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_ethereum_safe_tx_ack_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    bool has_to = false;
    bool has_value = false;
    bool has_data = false;
    bool has_operation = false;
    bool has_safe_tx_gas = false;
    bool has_base_gas = false;
    bool has_gas_price = false;
    bool has_gas_token = false;
    bool has_refund_receiver = false;
    bool has_nonce = false;
    bool has_chain_id = false;
    bool has_verifying_contract = false;

    wally_bzero(output, sizeof(*output));
    output->tx.data = output->data;
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
            wally_bzero(output, sizeof(*output));
            return false;
        }

        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_to
                || !trezor_safe_address_from_string(value, value_len, output->tx.to)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_to = true;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_value
                || !trezor_safe_copy_u256(output->tx.value, value, value_len)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_value = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_data || value_len > sizeof(output->data)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            if (value_len) {
                memcpy(output->data, value, value_len);
            }
            output->tx.data = output->data;
            output->tx.data_len = value_len;
            has_data = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || has_operation
                || !trezor_protobuf_read_varint_value(value, value_len, &raw)
                || raw > ETHEREUM_SAFE_TX_OPERATION_DELEGATE_CALL) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            output->tx.operation = (ethereum_safe_tx_operation_t)raw;
            has_operation = true;
        } else if (field_number == 5) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_safe_tx_gas
                || !trezor_safe_copy_u256(output->tx.safe_tx_gas, value, value_len)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_safe_tx_gas = true;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_base_gas
                || !trezor_safe_copy_u256(output->tx.base_gas, value, value_len)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_base_gas = true;
        } else if (field_number == 7) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_gas_price
                || !trezor_safe_copy_u256(output->tx.gas_price, value, value_len)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_gas_price = true;
        } else if (field_number == 8) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_gas_token
                || !trezor_safe_address_from_string(value, value_len, output->tx.gas_token)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_gas_token = true;
        } else if (field_number == 9) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_refund_receiver
                || !trezor_safe_address_from_string(value, value_len, output->tx.refund_receiver)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_refund_receiver = true;
        } else if (field_number == 10) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_nonce
                || !trezor_safe_copy_u256(output->tx.nonce, value, value_len)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_nonce = true;
        } else if (field_number == 11) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || has_chain_id
                || !trezor_protobuf_read_varint_value(value, value_len, &output->tx.chain_id)
                || output->tx.chain_id == 0) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_chain_id = true;
        } else if (field_number == 12) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_verifying_contract
                || !trezor_safe_address_from_string(value, value_len, output->tx.verifying_contract)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
            has_verifying_contract = true;
        } else {
            wally_bzero(output, sizeof(*output));
            return false;
        }
    }

    if (!has_to || !has_value || !has_operation || !has_safe_tx_gas || !has_base_gas || !has_gas_price
        || !has_gas_token || !has_refund_receiver || !has_nonce || !has_chain_id || !has_verifying_contract) {
        wally_bzero(output, sizeof(*output));
        return false;
    }
    if (!has_data) {
        output->tx.data = output->data;
        output->tx.data_len = 0;
    }
    return ethereum_safe_tx_validate(&output->tx);
}

bool trezor_ethereum_safe_typed_hash_bind(const trezor_ethereum_sign_typed_hash_t* const typed_hash,
    const ethereum_safe_tx_t* const safe_tx, uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN],
    ethereum_safe_tx_summary_t* const summary)
{
    if (!typed_hash || !safe_tx || !signing_hash || !summary || typed_hash->address_n_len == 0
        || !typed_hash->has_domain_separator_hash || !typed_hash->has_message_hash || typed_hash->has_encoded_network) {
        return false;
    }

    uint8_t domain_hash[KECCAK256_LEN];
    uint8_t message_hash[KECCAK256_LEN];
    uint8_t computed_signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    wally_bzero(domain_hash, sizeof(domain_hash));
    wally_bzero(message_hash, sizeof(message_hash));
    wally_bzero(computed_signing_hash, sizeof(computed_signing_hash));
    wally_bzero(summary, sizeof(*summary));
    wally_bzero(signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN);

    const bool ok = ethereum_safe_tx_domain_separator_hash(safe_tx->chain_id, safe_tx->verifying_contract, domain_hash)
        && memcmp(domain_hash, typed_hash->domain_separator_hash, sizeof(domain_hash)) == 0
        && ethereum_safe_tx_message_hash(safe_tx, message_hash)
        && memcmp(message_hash, typed_hash->message_hash, sizeof(message_hash)) == 0
        && ethereum_safe_tx_signing_hash(safe_tx, computed_signing_hash)
        && ethereum_safe_tx_preflight(safe_tx, summary);

    if (ok) {
        memcpy(signing_hash, computed_signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN);
    } else {
        wally_bzero(summary, sizeof(*summary));
    }

    wally_bzero(domain_hash, sizeof(domain_hash));
    wally_bzero(message_hash, sizeof(message_hash));
    wally_bzero(computed_signing_hash, sizeof(computed_signing_hash));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
