#ifndef AMALGAMATED_BUILD
#include "wire.h"

#include <stdbool.h>
#include <string.h>

static void trezor_wire_write_be16(uint8_t output[2], const uint16_t value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static void trezor_wire_write_be32(uint8_t output[4], const uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static uint16_t trezor_wire_read_be16(const uint8_t input[2])
{
    return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static uint32_t trezor_wire_read_be32(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) | ((uint32_t)input[2] << 8) | input[3];
}

bool trezor_wire_encoded_len(const size_t payload_len, size_t* const output_len)
{
    if (!output_len || payload_len > TREZOR_WIRE_MAX_PAYLOAD_LEN) {
        return false;
    }

    size_t chunks = 1;
    if (payload_len > TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_INIT_HEADER_LEN) {
        const size_t remaining = payload_len - (TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_INIT_HEADER_LEN);
        chunks += (remaining + (TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN) - 1)
            / (TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN);
    }

    *output_len = chunks * TREZOR_WIRE_CHUNK_SIZE;
    return true;
}

bool trezor_wire_encode_message(const uint16_t message_type, const uint8_t* const payload, const size_t payload_len,
    uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!output || !written || (!payload && payload_len) || payload_len > TREZOR_WIRE_MAX_PAYLOAD_LEN) {
        return false;
    }

    size_t required_len = 0;
    if (!trezor_wire_encoded_len(payload_len, &required_len) || output_len < required_len) {
        return false;
    }

    memset(output, 0, required_len);
    output[0] = TREZOR_WIRE_MARKER;
    output[1] = TREZOR_WIRE_MAGIC;
    output[2] = TREZOR_WIRE_MAGIC;
    trezor_wire_write_be16(output + 3, message_type);
    trezor_wire_write_be32(output + 5, (uint32_t)payload_len);

    size_t copied = 0;
    size_t chunk_offset = 0;
    size_t chunk_data_len = TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_INIT_HEADER_LEN;
    if (payload_len < chunk_data_len) {
        chunk_data_len = payload_len;
    }
    if (chunk_data_len) {
        memcpy(output + TREZOR_WIRE_INIT_HEADER_LEN, payload, chunk_data_len);
        copied = chunk_data_len;
    }
    chunk_offset += TREZOR_WIRE_CHUNK_SIZE;

    while (copied < payload_len) {
        output[chunk_offset] = TREZOR_WIRE_MARKER;
        chunk_data_len = payload_len - copied;
        if (chunk_data_len > TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN) {
            chunk_data_len = TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN;
        }
        memcpy(output + chunk_offset + TREZOR_WIRE_CONT_HEADER_LEN, payload + copied, chunk_data_len);
        copied += chunk_data_len;
        chunk_offset += TREZOR_WIRE_CHUNK_SIZE;
    }

    *written = required_len;
    return true;
}

bool trezor_wire_decode_message(const uint8_t* const input, const size_t input_len, uint16_t* const message_type,
    uint8_t* const payload, const size_t payload_cap, size_t* const payload_len)
{
    if (!input || !message_type || !payload_len || input_len == 0 || input_len % TREZOR_WIRE_CHUNK_SIZE != 0
        || input_len < TREZOR_WIRE_CHUNK_SIZE || (!payload && payload_cap)) {
        return false;
    }
    if (input[0] != TREZOR_WIRE_MARKER || input[1] != TREZOR_WIRE_MAGIC || input[2] != TREZOR_WIRE_MAGIC) {
        return false;
    }

    const uint16_t decoded_type = trezor_wire_read_be16(input + 3);
    const uint32_t decoded_len = trezor_wire_read_be32(input + 5);
    if (decoded_len > TREZOR_WIRE_MAX_PAYLOAD_LEN || decoded_len > payload_cap) {
        return false;
    }

    size_t required_len = 0;
    if (!trezor_wire_encoded_len(decoded_len, &required_len) || input_len < required_len) {
        return false;
    }

    size_t copied = 0;
    size_t chunk_offset = 0;
    size_t chunk_data_len = decoded_len;
    if (chunk_data_len > TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_INIT_HEADER_LEN) {
        chunk_data_len = TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_INIT_HEADER_LEN;
    }
    if (chunk_data_len) {
        memcpy(payload, input + TREZOR_WIRE_INIT_HEADER_LEN, chunk_data_len);
        copied = chunk_data_len;
    }
    chunk_offset += TREZOR_WIRE_CHUNK_SIZE;

    while (copied < decoded_len) {
        if (input[chunk_offset] != TREZOR_WIRE_MARKER) {
            return false;
        }
        chunk_data_len = decoded_len - copied;
        if (chunk_data_len > TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN) {
            chunk_data_len = TREZOR_WIRE_CHUNK_SIZE - TREZOR_WIRE_CONT_HEADER_LEN;
        }
        memcpy(payload + copied, input + chunk_offset + TREZOR_WIRE_CONT_HEADER_LEN, chunk_data_len);
        copied += chunk_data_len;
        chunk_offset += TREZOR_WIRE_CHUNK_SIZE;
    }

    *message_type = decoded_type;
    *payload_len = decoded_len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
