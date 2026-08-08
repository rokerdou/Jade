#ifndef KECCAK256_H_
#define KECCAK256_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KECCAK256_LEN 32

bool keccak256(const uint8_t* input, size_t input_len, uint8_t* output, size_t output_len);

#endif /* KECCAK256_H_ */
