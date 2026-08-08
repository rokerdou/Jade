#ifndef TREZOR_ETHEREUM_H_
#define TREZOR_ETHEREUM_H_

#include "../../wallet_core/wallet_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool show_display;
    bool has_show_display;
    bool chunkify;
    bool has_chunkify;
} trezor_ethereum_get_address_t;

bool trezor_ethereum_get_address_decode(
    const uint8_t* payload, size_t payload_len, trezor_ethereum_get_address_t* output);
bool trezor_ethereum_address_encode(const char* address, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_ETHEREUM_H_ */
