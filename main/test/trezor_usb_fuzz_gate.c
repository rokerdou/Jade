#include "protocols/trezor/dispatcher.h"
#include "protocols/trezor/messages.h"
#include "protocols/trezor/misc.h"
#include "protocols/trezor/protobuf.h"
#include "protocols/trezor/wire.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "trezor usb fuzz gate failed at %s:%d\n", __FILE__, __LINE__);                            \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (false)

static uint32_t xorshift32(uint32_t* const state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static int test_protobuf_malformed_inputs(void)
{
    trezor_protobuf_reader_t reader;
    uint32_t field_number = 0;
    uint8_t wire_type = 0;
    const uint8_t* value = NULL;
    size_t value_len = 0;

    const uint8_t unterminated_varint[] = { 0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    trezor_protobuf_reader_init(&reader, unterminated_varint, sizeof(unterminated_varint));
    CHECK(!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len));

    const uint8_t zero_field[] = { 0x00 };
    trezor_protobuf_reader_init(&reader, zero_field, sizeof(zero_field));
    CHECK(!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len));

    const uint8_t unsupported_wire_type[] = { 0x09, 0x00 };
    trezor_protobuf_reader_init(&reader, unsupported_wire_type, sizeof(unsupported_wire_type));
    CHECK(!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len));

    const uint8_t len_over_buffer[] = { 0x0a, 0x05, 0x01, 0x02 };
    trezor_protobuf_reader_init(&reader, len_over_buffer, sizeof(len_over_buffer));
    CHECK(!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len));

    const uint8_t len_over_field_max[] = { 0x0a, 0x81, 0x10 };
    trezor_protobuf_reader_init(&reader, len_over_field_max, sizeof(len_over_field_max));
    CHECK(!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len));

    uint8_t too_large_message[TREZOR_PROTOBUF_MAX_MESSAGE_LEN + 1U];
    memset(too_large_message, 0x08, sizeof(too_large_message));
    trezor_protobuf_reader_init(&reader, too_large_message, sizeof(too_large_message));
    CHECK(reader.len == 0);

    uint8_t output[8];
    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, sizeof(output));
    CHECK(!trezor_protobuf_write_bytes_field(&writer, 1, NULL, 1));
    CHECK(!trezor_protobuf_write_bytes_field(&writer, 0, NULL, 0));

    uint8_t oversized_field[TREZOR_PROTOBUF_MAX_FIELD_BYTES + 1U];
    CHECK(!trezor_protobuf_write_bytes_field(&writer, 1, oversized_field, sizeof(oversized_field)));

    return 0;
}

static int test_misc_get_entropy_bounds(void)
{
    uint32_t size = 0;
    uint8_t payload[16];
    trezor_protobuf_writer_t writer;

    trezor_protobuf_writer_init(&writer, payload, sizeof(payload));
    CHECK(trezor_protobuf_write_varint_field(&writer, 1, TREZOR_GET_ENTROPY_MAX_SIZE));
    CHECK(trezor_get_entropy_decode(payload, writer.len, &size));
    CHECK(size == TREZOR_GET_ENTROPY_MAX_SIZE);

    trezor_protobuf_writer_init(&writer, payload, sizeof(payload));
    CHECK(trezor_protobuf_write_varint_field(&writer, 1, TREZOR_GET_ENTROPY_MAX_SIZE + 1U));
    CHECK(trezor_get_entropy_decode(payload, writer.len, &size));
    CHECK(size == TREZOR_GET_ENTROPY_MAX_SIZE);

    trezor_protobuf_writer_init(&writer, payload, sizeof(payload));
    CHECK(trezor_protobuf_write_varint_field(&writer, 1, 16));
    CHECK(trezor_protobuf_write_varint_field(&writer, 1, 16));
    CHECK(!trezor_get_entropy_decode(payload, writer.len, &size));

    trezor_protobuf_writer_init(&writer, payload, sizeof(payload));
    CHECK(trezor_protobuf_write_bytes_field(&writer, 1, (const uint8_t*)"bad", 3));
    CHECK(!trezor_get_entropy_decode(payload, writer.len, &size));

    CHECK(!trezor_get_entropy_decode(NULL, 1, &size));
    CHECK(!trezor_get_entropy_decode(NULL, 0, NULL));

    uint8_t entropy[TREZOR_GET_ENTROPY_MAX_SIZE + 1U];
    uint8_t encoded[TREZOR_GET_ENTROPY_MAX_SIZE + 8U];
    size_t written = 0;
    CHECK(!trezor_entropy_encode(entropy, sizeof(entropy), encoded, sizeof(encoded), &written));
    CHECK(trezor_entropy_encode(entropy, TREZOR_GET_ENTROPY_MAX_SIZE, encoded, sizeof(encoded), &written));
    CHECK(written > 0);

    return 0;
}

static int test_wire_malformed_inputs(void)
{
    uint8_t payload[128];
    uint8_t wire[256];
    uint16_t message_type = 0;
    size_t payload_len = 0;
    size_t wire_len = 0;

    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }

    CHECK(trezor_wire_encode_message(TREZOR_MSG_GET_FEATURES, payload, sizeof(payload), wire, sizeof(wire), &wire_len));
    CHECK(trezor_wire_decode_message(wire, wire_len, &message_type, payload, sizeof(payload), &payload_len));
    CHECK(message_type == TREZOR_MSG_GET_FEATURES);
    CHECK(payload_len == sizeof(payload));

    uint8_t mutated[256];
    memcpy(mutated, wire, wire_len);
    mutated[0] = 0x00;
    CHECK(!trezor_wire_decode_message(mutated, wire_len, &message_type, payload, sizeof(payload), &payload_len));

    memcpy(mutated, wire, wire_len);
    mutated[64] = 0x00;
    CHECK(!trezor_wire_decode_message(mutated, wire_len, &message_type, payload, sizeof(payload), &payload_len));

    memcpy(mutated, wire, wire_len);
    mutated[5] = 0x00;
    mutated[6] = 0x00;
    mutated[7] = 0x40;
    mutated[8] = 0x01;
    CHECK(!trezor_wire_decode_message(mutated, wire_len, &message_type, payload, sizeof(payload), &payload_len));

    CHECK(!trezor_wire_decode_message(wire, wire_len - 1U, &message_type, payload, sizeof(payload), &payload_len));
    CHECK(!trezor_wire_decode_message(wire, wire_len, &message_type, payload, sizeof(payload) - 1U, &payload_len));

    size_t encoded_len = 0;
    CHECK(trezor_wire_encoded_len(TREZOR_WIRE_MAX_PAYLOAD_LEN, &encoded_len));
    CHECK(!trezor_wire_encoded_len(TREZOR_WIRE_MAX_PAYLOAD_LEN + 1U, &encoded_len));
    CHECK(!trezor_wire_encode_message(TREZOR_MSG_GET_FEATURES, payload, TREZOR_WIRE_MAX_PAYLOAD_LEN + 1U, wire,
        sizeof(wire), &wire_len));

    return 0;
}

static int test_deterministic_parser_fuzz(void)
{
    uint32_t rng = 0x4aade001U;
    uint8_t input[320];
    uint8_t payload[512];
    uint16_t message_type = 0;
    size_t payload_len = 0;

    for (size_t round = 0; round < 512; ++round) {
        const size_t input_len = 1U + (xorshift32(&rng) % sizeof(input));
        for (size_t i = 0; i < input_len; ++i) {
            input[i] = (uint8_t)xorshift32(&rng);
        }

        trezor_protobuf_reader_t reader;
        trezor_protobuf_reader_init(&reader, input, input_len);
        size_t steps = 0;
        while (reader.pos < reader.len && steps < input_len + 1U) {
            uint32_t field_number = 0;
            uint8_t wire_type = 0;
            const uint8_t* value = NULL;
            size_t value_len = 0;
            if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
                break;
            }
            CHECK(field_number != 0);
            CHECK(wire_type == TREZOR_PROTOBUF_WIRE_VARINT || wire_type == TREZOR_PROTOBUF_WIRE_LEN);
            CHECK(value || value_len == 0);
            ++steps;
        }
        CHECK(steps <= input_len + 1U);

        const size_t wire_len = input_len - (input_len % TREZOR_WIRE_CHUNK_SIZE);
        if (wire_len) {
            (void)trezor_wire_decode_message(input, wire_len, &message_type, payload, sizeof(payload), &payload_len);
        }
    }

    return 0;
}

static int test_dispatcher_sensitive_surface(void)
{
    static const uint32_t allowed_messages[] = {
        TREZOR_MSG_INITIALIZE,
        TREZOR_MSG_GET_FEATURES,
        TREZOR_MSG_CANCEL,
        TREZOR_MSG_END_SESSION,
        TREZOR_MSG_APPLY_FLAGS,
        TREZOR_MSG_BUTTON_ACK,
        TREZOR_MSG_GET_ENTROPY,
        TREZOR_MSG_GET_ADDRESS,
        TREZOR_MSG_GET_PUBLIC_KEY,
        TREZOR_MSG_SIGN_TX,
        TREZOR_MSG_TX_ACK,
        TREZOR_MSG_ETHEREUM_GET_ADDRESS,
        TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY,
        TREZOR_MSG_ETHEREUM_SIGN_TX,
        TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559,
        TREZOR_MSG_ETHEREUM_TX_ACK,
        TREZOR_MSG_ETHEREUM_SIGN_TYPED_HASH,
        TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK,
        TREZOR_MSG_ONEKEY_SIGN_PSBT,
    };
    static const uint32_t sensitive_or_unsupported_messages[] = {
        TREZOR_MSG_LOAD_DEVICE,
        TREZOR_MSG_RESET_DEVICE,
        TREZOR_MSG_BACKUP_DEVICE,
        TREZOR_MSG_RECOVERY_DEVICE,
        TREZOR_MSG_SIGN_MESSAGE,
        TREZOR_MSG_SIGN_IDENTITY,
        TREZOR_MSG_GET_ECDH_SESSION_KEY,
        TREZOR_MSG_CIPHER_KEY_VALUE,
        TREZOR_MSG_PASSPHRASE_ACK,
        TREZOR_MSG_UNLOCK_PATH,
        TREZOR_MSG_TX_ACK_PAYMENT_REQUEST,
        TREZOR_MSG_ETHEREUM_TYPED_DATA_SIGNATURE,
        TREZOR_MSG_ONEKEY_SIGNED_PSBT,
        0xffffU,
    };

    for (size_t i = 0; i < sizeof(allowed_messages) / sizeof(allowed_messages[0]); ++i) {
        CHECK(trezor_dispatcher_message_allowed(allowed_messages[i]));
        CHECK(!trezor_dispatcher_message_sensitive_or_unsupported(allowed_messages[i]));
    }

    for (size_t i = 0; i < sizeof(sensitive_or_unsupported_messages) / sizeof(sensitive_or_unsupported_messages[0]);
         ++i) {
        CHECK(!trezor_dispatcher_message_allowed(sensitive_or_unsupported_messages[i]));
        CHECK(trezor_dispatcher_message_sensitive_or_unsupported(sensitive_or_unsupported_messages[i]));
    }

    return 0;
}

int main(void)
{
    CHECK(test_protobuf_malformed_inputs() == 0);
    CHECK(test_misc_get_entropy_bounds() == 0);
    CHECK(test_wire_malformed_inputs() == 0);
    CHECK(test_deterministic_parser_fuzz() == 0);
    CHECK(test_dispatcher_sensitive_surface() == 0);

    printf("PASS trezor_usb_fuzz_gate\n");
    return 0;
}
