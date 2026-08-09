#ifndef AMALGAMATED_BUILD
#include "definitions.h"

#include "../protobuf.h"

#include <string.h>
#include <wally_crypto.h>

#ifndef TREZOR_ETHEREUM_DEFINITIONS_HOST_TEST
#include <sodium/core.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_sign.h>
#endif

#define TREZOR_DEFINITION_MAGIC "trzd1"
#define TREZOR_DEFINITION_MAGIC_LEN 5
#define TREZOR_DEFINITION_TYPE_ETHEREUM_NETWORK 0
#define TREZOR_DEFINITION_TYPE_ETHEREUM_TOKEN 1
#define TREZOR_DEFINITION_MIN_DATA_VERSION 1768042093U
#define TREZOR_DEFINITION_PUBLIC_KEYS_LEN 3
#define TREZOR_DEFINITION_THRESHOLD 2
#define TREZOR_DEFINITION_SIGNATURE_LEN 64
#define TREZOR_DEFINITION_MAX_PROOF_ENTRIES 32

#ifndef TREZOR_ETHEREUM_DEFINITIONS_HOST_TEST
static const uint8_t TREZOR_DEFINITION_PUBLIC_KEYS[TREZOR_DEFINITION_PUBLIC_KEYS_LEN][32] = {
    { 0x43, 0x34, 0x99, 0x63, 0x43, 0x62, 0x3e, 0x46, 0x2f, 0x0f, 0xc9, 0x33, 0x11, 0xfe, 0xf1, 0x48,
        0x4c, 0xa2, 0x3d, 0x2f, 0xf1, 0xee, 0xc6, 0xdf, 0x1f, 0xa8, 0xeb, 0x7e, 0x35, 0x73, 0xb3, 0xdb },
    { 0xa9, 0xa2, 0x2c, 0xc2, 0x65, 0xa0, 0xcb, 0x1d, 0x6c, 0xb3, 0x29, 0xbc, 0x0e, 0x60, 0xbc, 0x45,
        0xdf, 0x76, 0xb9, 0xab, 0x28, 0xfb, 0x87, 0xb6, 0x11, 0x36, 0xfe, 0xaf, 0x8d, 0x8f, 0xdc, 0x96 },
    { 0xb8, 0xd2, 0xb2, 0x1d, 0xe2, 0x71, 0x24, 0xf0, 0x51, 0x1f, 0x90, 0x3a, 0xe7, 0xe6, 0x0e, 0x07,
        0x96, 0x18, 0x10, 0xa0, 0xb8, 0xf2, 0x8e, 0xa7, 0x55, 0xfa, 0x50, 0x36, 0x7a, 0x8a, 0x2b, 0x8b },
};
#endif

static bool read_u16_le(const uint8_t* const bytes, const size_t len, const size_t offset, uint16_t* const output)
{
    if (!bytes || !output || offset > len || len - offset < 2) {
        return false;
    }
    *output = (uint16_t)bytes[offset] | ((uint16_t)bytes[offset + 1] << 8);
    return true;
}

static bool read_u32_le(const uint8_t* const bytes, const size_t len, const size_t offset, uint32_t* const output)
{
    if (!bytes || !output || offset > len || len - offset < 4) {
        return false;
    }
    *output = (uint32_t)bytes[offset] | ((uint32_t)bytes[offset + 1] << 8) | ((uint32_t)bytes[offset + 2] << 16)
        | ((uint32_t)bytes[offset + 3] << 24);
    return true;
}

static bool sha256_prefixed(const uint8_t prefix, const uint8_t* const bytes, const size_t bytes_len,
    uint8_t output[SHA256_LEN])
{
    if ((!bytes && bytes_len) || !output || bytes_len > TREZOR_PROTOBUF_MAX_FIELD_BYTES) {
        return false;
    }

    uint8_t material[1 + TREZOR_PROTOBUF_MAX_FIELD_BYTES];
    material[0] = prefix;
    if (bytes_len) {
        memcpy(material + 1, bytes, bytes_len);
    }
    const bool ok = wally_sha256(material, bytes_len + 1, output, SHA256_LEN) == WALLY_OK;
    wally_bzero(material, sizeof(material));
    return ok;
}

static bool definition_merkle_root(const uint8_t* const definition, const size_t definition_len,
    const size_t payload_end, const uint8_t* const proof, const size_t proof_len, uint8_t root[SHA256_LEN])
{
    if (!definition || payload_end > definition_len || !proof || proof_len > TREZOR_DEFINITION_MAX_PROOF_ENTRIES
        || !root || !sha256_prefixed(0x00, definition, payload_end, root)) {
        return false;
    }

    for (size_t i = 0; i < proof_len; ++i) {
        const uint8_t* const entry = proof + (i * SHA256_LEN);
        uint8_t node[1 + (2 * SHA256_LEN)];
        node[0] = 0x01;
        if (memcmp(root, entry, SHA256_LEN) <= 0) {
            memcpy(node + 1, root, SHA256_LEN);
            memcpy(node + 1 + SHA256_LEN, entry, SHA256_LEN);
        } else {
            memcpy(node + 1, entry, SHA256_LEN);
            memcpy(node + 1 + SHA256_LEN, root, SHA256_LEN);
        }
        if (wally_sha256(node, sizeof(node), root, SHA256_LEN) != WALLY_OK) {
            wally_bzero(node, sizeof(node));
            return false;
        }
        wally_bzero(node, sizeof(node));
    }
    return true;
}

#ifdef TREZOR_ETHEREUM_DEFINITIONS_HOST_TEST
bool trezor_ethereum_definitions_host_verify(
    const uint8_t root[SHA256_LEN], uint8_t sigmask, const uint8_t signature[TREZOR_DEFINITION_SIGNATURE_LEN]);

static bool definition_cosi_verify(const uint8_t root[SHA256_LEN], const uint8_t sigmask,
    const uint8_t signature[TREZOR_DEFINITION_SIGNATURE_LEN])
{
    return trezor_ethereum_definitions_host_verify(root, sigmask, signature);
}
#else
static bool definition_cosi_verify(const uint8_t root[SHA256_LEN], const uint8_t sigmask,
    const uint8_t signature[TREZOR_DEFINITION_SIGNATURE_LEN])
{
    if (!root || !signature || (sigmask & ~((1U << TREZOR_DEFINITION_PUBLIC_KEYS_LEN) - 1U)) != 0
        || sodium_init() < 0) {
        return false;
    }

    uint8_t combined_key[32];
    size_t selected = 0;
    wally_bzero(combined_key, sizeof(combined_key));
    for (size_t i = 0; i < TREZOR_DEFINITION_PUBLIC_KEYS_LEN; ++i) {
        if ((sigmask & (1U << i)) == 0) {
            continue;
        }
        if (crypto_core_ed25519_is_valid_point(TREZOR_DEFINITION_PUBLIC_KEYS[i]) != 1) {
            return false;
        }
        if (selected == 0) {
            memcpy(combined_key, TREZOR_DEFINITION_PUBLIC_KEYS[i], sizeof(combined_key));
        } else if (crypto_core_ed25519_add(combined_key, combined_key, TREZOR_DEFINITION_PUBLIC_KEYS[i]) != 0) {
            wally_bzero(combined_key, sizeof(combined_key));
            return false;
        }
        ++selected;
    }

    const bool ok = selected >= TREZOR_DEFINITION_THRESHOLD
        && crypto_sign_verify_detached(signature, root, SHA256_LEN, combined_key) == 0;
    wally_bzero(combined_key, sizeof(combined_key));
    return ok;
}
#endif

static bool copy_printable_string(char* const output, const size_t output_len, const uint8_t* const value,
    const size_t value_len)
{
    if (!output || output_len == 0 || !value || value_len == 0 || value_len >= output_len) {
        return false;
    }
    for (size_t i = 0; i < value_len; ++i) {
        if (value[i] < 0x20 || value[i] > 0x7e) {
            return false;
        }
    }
    memcpy(output, value, value_len);
    output[value_len] = '\0';
    return true;
}

static bool decode_network_payload(
    const uint8_t* const payload, const size_t payload_len, uint64_t* const chain_id)
{
    if (!payload || !chain_id) {
        return false;
    }

    bool has_chain_id = false;
    bool has_symbol = false;
    bool has_slip44 = false;
    bool has_name = false;
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
            if (has_chain_id || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, chain_id) || *chain_id == 0) {
                return false;
            }
            has_chain_id = true;
        } else if (field_number == 2) {
            char symbol[ETHEREUM_TOKEN_SYMBOL_MAX_LEN];
            if (has_symbol || wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !copy_printable_string(symbol, sizeof(symbol), value, value_len)) {
                return false;
            }
            has_symbol = true;
        } else if (field_number == 3) {
            if (has_slip44 || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > UINT32_MAX) {
                return false;
            }
            has_slip44 = true;
        } else if (field_number == 4) {
            char name[ETHEREUM_TOKEN_NAME_MAX_LEN];
            if (has_name || wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !copy_printable_string(name, sizeof(name), value, value_len)) {
                return false;
            }
            has_name = true;
        } else {
            return false;
        }
    }

    return has_chain_id && has_symbol && has_slip44 && has_name;
}

static bool decode_token_payload(
    const uint8_t* const payload, const size_t payload_len, ethereum_token_metadata_t* const token)
{
    if (!payload || !token) {
        return false;
    }

    bool has_address = false;
    bool has_chain_id = false;
    bool has_symbol = false;
    bool has_decimals = false;
    bool has_name = false;
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
            if (has_address || wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len != ETHEREUM_ADDRESS_LEN) {
                return false;
            }
            memcpy(token->address, value, ETHEREUM_ADDRESS_LEN);
            has_address = true;
        } else if (field_number == 2) {
            if (has_chain_id || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &token->chain_id) || token->chain_id == 0) {
                return false;
            }
            has_chain_id = true;
        } else if (field_number == 3) {
            if (has_symbol || wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !copy_printable_string(token->symbol, sizeof(token->symbol), value, value_len)) {
                return false;
            }
            has_symbol = true;
        } else if (field_number == 4) {
            if (has_decimals || wire_type != TREZOR_PROTOBUF_WIRE_VARINT
                || !trezor_protobuf_read_varint_value(value, value_len, &raw)
                || raw > ETHEREUM_TOKEN_DECIMALS_MAX) {
                return false;
            }
            token->decimals = (uint32_t)raw;
            has_decimals = true;
        } else if (field_number == 5) {
            if (has_name || wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || !copy_printable_string(token->name, sizeof(token->name), value, value_len)) {
                return false;
            }
            has_name = true;
        } else {
            return false;
        }
    }

    return has_address && has_chain_id && has_symbol && has_decimals && has_name;
}

static bool decode_signed_definition(const uint8_t* const definition, const size_t definition_len,
    const uint8_t expected_type, trezor_ethereum_definitions_t* const output)
{
    if (!definition || !definition_len || !output || definition_len > TREZOR_PROTOBUF_MAX_FIELD_BYTES
        || definition_len < TREZOR_DEFINITION_MAGIC_LEN + 1 + 4 + 2 + 1 + TREZOR_DEFINITION_SIGNATURE_LEN
        || memcmp(definition, TREZOR_DEFINITION_MAGIC, TREZOR_DEFINITION_MAGIC_LEN) != 0) {
        return false;
    }

    size_t offset = TREZOR_DEFINITION_MAGIC_LEN;
    if (definition[offset++] != expected_type) {
        return false;
    }

    uint32_t data_version = 0;
    if (!read_u32_le(definition, definition_len, offset, &data_version)
        || data_version < TREZOR_DEFINITION_MIN_DATA_VERSION) {
        return false;
    }
    offset += 4;

    uint16_t protobuf_len = 0;
    if (!read_u16_le(definition, definition_len, offset, &protobuf_len)) {
        return false;
    }
    offset += 2;
    if (protobuf_len == 0 || protobuf_len > definition_len - offset) {
        return false;
    }

    const uint8_t* const protobuf_payload = definition + offset;
    offset += protobuf_len;
    const size_t payload_end = offset;
    if (offset >= definition_len) {
        return false;
    }

    const size_t proof_len = definition[offset++];
    if (proof_len > TREZOR_DEFINITION_MAX_PROOF_ENTRIES || proof_len > (definition_len - offset) / SHA256_LEN) {
        return false;
    }
    const uint8_t* const proof = definition + offset;
    offset += proof_len * SHA256_LEN;
    if (definition_len - offset != 1 + TREZOR_DEFINITION_SIGNATURE_LEN) {
        return false;
    }

    const uint8_t sigmask = definition[offset++];
    const uint8_t* const signature = definition + offset;
    uint8_t root[SHA256_LEN];
    bool ok = definition_merkle_root(definition, definition_len, payload_end, proof, proof_len, root)
        && definition_cosi_verify(root, sigmask, signature);
    if (ok && expected_type == TREZOR_DEFINITION_TYPE_ETHEREUM_NETWORK) {
        output->has_network = true;
        ok = decode_network_payload(protobuf_payload, protobuf_len, &output->network_chain_id);
    } else if (ok && expected_type == TREZOR_DEFINITION_TYPE_ETHEREUM_TOKEN) {
        output->has_token = true;
        ok = decode_token_payload(protobuf_payload, protobuf_len, &output->token);
    }
    wally_bzero(root, sizeof(root));
    return ok;
}

bool trezor_ethereum_definitions_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_ethereum_definitions_t* const output)
{
    if (!output || (!payload && payload_len)) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    if (payload_len == 0) {
        return true;
    }

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (reader.len == 0) {
        return false;
    }

    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)
            || wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len == 0) {
            wally_bzero(output, sizeof(*output));
            return false;
        }
        if (field_number == 1) {
            if (output->has_network
                || !decode_signed_definition(value, value_len, TREZOR_DEFINITION_TYPE_ETHEREUM_NETWORK, output)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
        } else if (field_number == 2) {
            if (output->has_token
                || !decode_signed_definition(value, value_len, TREZOR_DEFINITION_TYPE_ETHEREUM_TOKEN, output)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
        } else {
            wally_bzero(output, sizeof(*output));
            return false;
        }
    }

    return true;
}
#endif /* AMALGAMATED_BUILD */
