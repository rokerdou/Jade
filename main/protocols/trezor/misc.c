#ifndef AMALGAMATED_BUILD
#include "misc.h"

#include "protobuf.h"

#include <string.h>

bool trezor_get_entropy_decode(const uint8_t* const payload, const size_t payload_len, uint32_t* const size)
{
    if (!size || (!payload && payload_len)) {
        return false;
    }
    *size = 0;

    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (reader.len != payload_len) {
        return false;
    }

    bool saw_size = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        uint64_t raw_size = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)
            || field_number != 1 || wire_type != TREZOR_PROTOBUF_WIRE_VARINT || saw_size
            || !trezor_protobuf_read_varint_value(value, value_len, &raw_size) || raw_size > UINT32_MAX) {
            return false;
        }
        *size = raw_size > TREZOR_GET_ENTROPY_MAX_SIZE ? TREZOR_GET_ENTROPY_MAX_SIZE : (uint32_t)raw_size;
        saw_size = true;
    }

    return saw_size;
}

bool trezor_entropy_encode(const uint8_t* const entropy, const size_t entropy_len, uint8_t* const output,
    const size_t output_len, size_t* const output_written)
{
    if (!output || !output_written || (!entropy && entropy_len) || entropy_len > TREZOR_GET_ENTROPY_MAX_SIZE) {
        return false;
    }
    *output_written = 0;

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_bytes_field(&writer, 1, entropy, entropy_len)) {
        memset(output, 0, output_len);
        return false;
    }

    *output_written = writer.len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
