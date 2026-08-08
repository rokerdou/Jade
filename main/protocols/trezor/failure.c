#ifndef AMALGAMATED_BUILD
#include "failure.h"

#include "protobuf.h"

#include <string.h>
#include <wally_crypto.h>

#define TREZOR_FAILURE_MAX_MESSAGE_LEN 80

bool trezor_failure_encode(const trezor_failure_type_t code, const char* const message, uint8_t* const output,
    const size_t output_len, size_t* const written)
{
    if (!message || !output || !written || strlen(message) > TREZOR_FAILURE_MAX_MESSAGE_LEN) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);
    if (!trezor_protobuf_write_varint_field(&writer, 1, code)
        || !trezor_protobuf_write_string_field(&writer, 2, message)) {
        wally_bzero(output, output_len);
        return false;
    }

    *written = writer.len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
