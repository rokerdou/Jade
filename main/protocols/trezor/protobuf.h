#ifndef TREZOR_PROTOBUF_H_
#define TREZOR_PROTOBUF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_PROTOBUF_MAX_MESSAGE_LEN 16384
#define TREZOR_PROTOBUF_MAX_FIELD_BYTES 2048

typedef enum {
    TREZOR_PROTOBUF_WIRE_VARINT = 0,
    TREZOR_PROTOBUF_WIRE_LEN = 2,
} trezor_protobuf_wire_type_t;

typedef struct {
    const uint8_t* bytes;
    size_t len;
    size_t pos;
} trezor_protobuf_reader_t;

typedef struct {
    uint8_t* bytes;
    size_t len;
    size_t cap;
} trezor_protobuf_writer_t;

void trezor_protobuf_reader_init(trezor_protobuf_reader_t* reader, const uint8_t* bytes, size_t len);
// Returns false on malformed input and at EOF. Callers that scan all fields must loop on reader.pos < reader.len.
bool trezor_protobuf_reader_next(trezor_protobuf_reader_t* reader, uint32_t* field_number, uint8_t* wire_type,
    const uint8_t** value, size_t* value_len);
bool trezor_protobuf_skip_value(
    trezor_protobuf_reader_t* reader, uint8_t wire_type, const uint8_t** value, size_t* value_len);
bool trezor_protobuf_read_varint_value(const uint8_t* value, size_t value_len, uint64_t* output);

void trezor_protobuf_writer_init(trezor_protobuf_writer_t* writer, uint8_t* bytes, size_t cap);
bool trezor_protobuf_write_varint_field(trezor_protobuf_writer_t* writer, uint32_t field_number, uint64_t value);
bool trezor_protobuf_write_bool_field(trezor_protobuf_writer_t* writer, uint32_t field_number, bool value);
bool trezor_protobuf_write_bytes_field(
    trezor_protobuf_writer_t* writer, uint32_t field_number, const uint8_t* value, size_t value_len);
bool trezor_protobuf_write_string_field(trezor_protobuf_writer_t* writer, uint32_t field_number, const char* value);

#endif /* TREZOR_PROTOBUF_H_ */
