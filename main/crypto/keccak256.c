#ifndef AMALGAMATED_BUILD
#include "keccak256.h"

#include <string.h>
#include <wally_crypto.h>

#define KECCAK256_RATE 136
#define KECCAK256_STATE_WORDS 25

static const uint64_t KECCAKF_RNDC[24] = { 0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL,
    0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL,
    0x8000000080008008ULL };

static const int KECCAKF_ROTC[24]
    = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };

static const int KECCAKF_PILN[24]
    = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

static void keccak256_permute(uint64_t state[KECCAK256_STATE_WORDS])
{
    uint64_t bc[5];

    for (int round = 0; round < 24; ++round) {
        for (int i = 0; i < 5; ++i) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        for (int i = 0; i < 5; ++i) {
            const uint64_t t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (int j = 0; j < KECCAK256_STATE_WORDS; j += 5) {
                state[j + i] ^= t;
            }
        }

        uint64_t t = state[1];
        for (int i = 0; i < 24; ++i) {
            const int j = KECCAKF_PILN[i];
            bc[0] = state[j];
            state[j] = (t << KECCAKF_ROTC[i]) | (t >> (64 - KECCAKF_ROTC[i]));
            t = bc[0];
        }

        for (int j = 0; j < KECCAK256_STATE_WORDS; j += 5) {
            for (int i = 0; i < 5; ++i) {
                bc[i] = state[j + i];
            }
            for (int i = 0; i < 5; ++i) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        state[0] ^= KECCAKF_RNDC[round];
    }
}

bool keccak256(const uint8_t* const input, const size_t input_len, uint8_t* const output, const size_t output_len)
{
    if ((!input && input_len) || !output || output_len != KECCAK256_LEN) {
        return false;
    }

    uint64_t state[KECCAK256_STATE_WORDS] = { 0 };
    size_t offset = 0;

    while (input_len - offset >= KECCAK256_RATE) {
        for (size_t i = 0; i < KECCAK256_RATE; ++i) {
            ((uint8_t*)state)[i] ^= input[offset + i];
        }
        keccak256_permute(state);
        offset += KECCAK256_RATE;
    }

    const size_t remaining = input_len - offset;
    for (size_t i = 0; i < remaining; ++i) {
        ((uint8_t*)state)[i] ^= input[offset + i];
    }

    ((uint8_t*)state)[remaining] ^= 0x01;
    ((uint8_t*)state)[KECCAK256_RATE - 1] ^= 0x80;
    keccak256_permute(state);

    memcpy(output, state, output_len);
    wally_bzero(state, sizeof(state));
    return true;
}
#endif /* AMALGAMATED_BUILD */
