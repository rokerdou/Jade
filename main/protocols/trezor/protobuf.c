#ifndef AMALGAMATED_BUILD
#include "protobuf.h"

#include <string.h>

#define TREZOR_PROTOBUF_MAX_VARINT_BYTES 10

static bool trezor_protobuf_append(trezor_protobuf_writer_t* const writer, const uint8_t* const bytes, const size_t len)
{
    if (!writer || (!bytes && len) || len > writer->cap - writer->len) {
        return false;
    }
    if (len) {
        memcpy(writer->bytes + writer->len, bytes, len);
        writer->len += len;
    }
    return true;
}

static bool trezor_protobuf_read_varint(
    const uint8_t* const bytes, const size_t len, size_t* const consumed, uint64_t* const output)
{
    if (!bytes || !len || !consumed || !output) {
        return false;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < len && i < TREZOR_PROTOBUF_MAX_VARINT_BYTES; ++i) {
        const uint8_t byte = bytes[i];
        if (i == TREZOR_PROTOBUF_MAX_VARINT_BYTES - 1 && (byte & 0xfe) != 0) {
            return false;
        }
        value |= ((uint64_t)(byte & 0x7f)) << (7 * i);
        if ((byte & 0x80) == 0) {
            *consumed = i + 1;
            *output = value;
            return true;
        }
    }
    return false;
}

static bool trezor_protobuf_write_varint(trezor_protobuf_writer_t* const writer, uint64_t value)
{
    uint8_t encoded[TREZOR_PROTOBUF_MAX_VARINT_BYTES];
    size_t len = 0;
    do {
        uint8_t byte = (uint8_t)(value & 0x7f);
        value >>= 7;
        if (value) {
            byte |= 0x80;
        }
        encoded[len++] = byte;
    } while (value && len < sizeof(encoded));

    return value == 0 && trezor_protobuf_append(writer, encoded, len);
}

void trezor_protobuf_reader_init(trezor_protobuf_reader_t* const reader, const uint8_t* const bytes, const size_t len)
{
    if (!reader) {
        return;
    }
    reader->bytes = bytes;
    reader->len = bytes && len <= TREZOR_PROTOBUF_MAX_MESSAGE_LEN ? len : 0;
    reader->pos = 0;
}

bool trezor_protobuf_skip_value(trezor_protobuf_reader_t* const reader, const uint8_t wire_type,
    const uint8_t** const value, size_t* const value_len)
{
    if (!reader || reader->pos > reader->len || !value || !value_len) {
        return false;
    }

    *value = NULL;
    *value_len = 0;
    if (wire_type == TREZOR_PROTOBUF_WIRE_VARINT) {
        size_t consumed = 0;
        uint64_t ignored = 0;
        if (!trezor_protobuf_read_varint(reader->bytes + reader->pos, reader->len - reader->pos, &consumed, &ignored)) {
            return false;
        }
        *value = reader->bytes + reader->pos;
        *value_len = consumed;
        reader->pos += consumed;
        return true;
    }

    if (wire_type == TREZOR_PROTOBUF_WIRE_LEN) {
        size_t consumed = 0;
        uint64_t len = 0;
        if (!trezor_protobuf_read_varint(reader->bytes + reader->pos, reader->len - reader->pos, &consumed, &len)
            || len > TREZOR_PROTOBUF_MAX_FIELD_BYTES || len > reader->len - reader->pos - consumed) {
            return false;
        }
        reader->pos += consumed;
        *value = reader->bytes + reader->pos;
        *value_len = (size_t)len;
        reader->pos += (size_t)len;
        return true;
    }

    return false;
}

bool trezor_protobuf_reader_next(trezor_protobuf_reader_t* const reader, uint32_t* const field_number,
    uint8_t* const wire_type, const uint8_t** const value, size_t* const value_len)
{
    if (!reader || !field_number || !wire_type || !value || !value_len || reader->pos > reader->len) {
        return false;
    }
    if (reader->pos == reader->len) {
        return false;
    }

    size_t consumed = 0;
    uint64_t key = 0;
    if (!trezor_protobuf_read_varint(reader->bytes + reader->pos, reader->len - reader->pos, &consumed, &key)
        || (key >> 3) == 0 || (key >> 3) > UINT32_MAX) {
        return false;
    }
    reader->pos += consumed;
    *field_number = (uint32_t)(key >> 3);
    *wire_type = (uint8_t)(key & 0x07);
    return trezor_protobuf_skip_value(reader, *wire_type, value, value_len);
}

bool trezor_protobuf_read_varint_value(const uint8_t* const value, const size_t value_len, uint64_t* const output)
{
    size_t consumed = 0;
    return trezor_protobuf_read_varint(value, value_len, &consumed, output) && consumed == value_len;
}

void trezor_protobuf_writer_init(trezor_protobuf_writer_t* const writer, uint8_t* const bytes, const size_t cap)
{
    if (!writer) {
        return;
    }
    writer->bytes = bytes;
    writer->len = 0;
    writer->cap = bytes ? cap : 0;
}

bool trezor_protobuf_write_varint_field(
    trezor_protobuf_writer_t* const writer, const uint32_t field_number, const uint64_t value)
{
    if (!field_number) {
        return false;
    }
    const uint64_t key = ((uint64_t)field_number << 3) | TREZOR_PROTOBUF_WIRE_VARINT;
    return trezor_protobuf_write_varint(writer, key) && trezor_protobuf_write_varint(writer, value);
}

bool trezor_protobuf_write_bool_field(
    trezor_protobuf_writer_t* const writer, const uint32_t field_number, const bool value)
{
    return trezor_protobuf_write_varint_field(writer, field_number, value ? 1 : 0);
}

bool trezor_protobuf_write_bytes_field(trezor_protobuf_writer_t* const writer, const uint32_t field_number,
    const uint8_t* const value, const size_t value_len)
{
    if (!field_number || (!value && value_len) || value_len > TREZOR_PROTOBUF_MAX_FIELD_BYTES) {
        return false;
    }
    const uint64_t key = ((uint64_t)field_number << 3) | TREZOR_PROTOBUF_WIRE_LEN;
    return trezor_protobuf_write_varint(writer, key) && trezor_protobuf_write_varint(writer, value_len)
        && trezor_protobuf_append(writer, value, value_len);
}

bool trezor_protobuf_write_string_field(
    trezor_protobuf_writer_t* const writer, const uint32_t field_number, const char* const value)
{
    if (!field_number || !value) {
        return false;
    }
    const size_t len = strlen(value);
    return trezor_protobuf_write_bytes_field(writer, field_number, (const uint8_t*)value, len);
}
#endif /* AMALGAMATED_BUILD */
