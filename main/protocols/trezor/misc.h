#ifndef TREZOR_MISC_H_
#define TREZOR_MISC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_GET_ENTROPY_MAX_SIZE 1024U

bool trezor_get_entropy_decode(const uint8_t* payload, size_t payload_len, uint32_t* size);
bool trezor_entropy_encode(
    const uint8_t* entropy, size_t entropy_len, uint8_t* output, size_t output_len, size_t* output_written);

#endif /* TREZOR_MISC_H_ */
