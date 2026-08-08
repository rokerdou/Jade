#ifndef TREZOR_FAILURE_H_
#define TREZOR_FAILURE_H_

#include "messages.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool trezor_failure_encode(
    trezor_failure_type_t code, const char* message, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_FAILURE_H_ */
