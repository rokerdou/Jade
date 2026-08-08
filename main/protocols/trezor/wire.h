#ifndef TREZOR_WIRE_H_
#define TREZOR_WIRE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_WIRE_CHUNK_SIZE 64
#define TREZOR_WIRE_INIT_HEADER_LEN 9
#define TREZOR_WIRE_CONT_HEADER_LEN 1
#define TREZOR_WIRE_MARKER 0x3f
#define TREZOR_WIRE_MAGIC 0x23
#define TREZOR_WIRE_MAX_PAYLOAD_LEN 16384

bool trezor_wire_encoded_len(size_t payload_len, size_t* output_len);
bool trezor_wire_encode_message(uint16_t message_type, const uint8_t* payload, size_t payload_len, uint8_t* output,
    size_t output_len, size_t* written);
bool trezor_wire_decode_message(const uint8_t* input, size_t input_len, uint16_t* message_type, uint8_t* payload,
    size_t payload_cap, size_t* payload_len);

#endif /* TREZOR_WIRE_H_ */
