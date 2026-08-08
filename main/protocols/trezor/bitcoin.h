#ifndef TREZOR_BITCOIN_H_
#define TREZOR_BITCOIN_H_

#include "../../wallet_core/wallet_core.h"
#include "../../chains/bitcoin/address.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_BITCOIN_COIN_NAME_MAX_LEN 16

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool has_coin_name;
    char coin_name[TREZOR_BITCOIN_COIN_NAME_MAX_LEN];
    bool has_show_display;
    bool show_display;
    bool has_script_type;
    uint32_t script_type;
    bool has_ignore_xpub_magic;
    bool ignore_xpub_magic;
    bool has_chunkify;
    bool chunkify;
} trezor_bitcoin_get_address_t;

bool trezor_bitcoin_get_address_decode(
    const uint8_t* payload, size_t payload_len, trezor_bitcoin_get_address_t* output);
bool trezor_bitcoin_address_encode(const char* address, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_BITCOIN_H_ */
