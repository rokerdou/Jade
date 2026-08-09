#ifndef TREZOR_WALLET_ADAPTER_H_
#define TREZOR_WALLET_ADAPTER_H_

#include "features.h"
#include "session.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char* device_id;
    const uint8_t* session_id;
    size_t session_id_len;
    trezor_session_state_t* state;
    trezor_session_initialize_callback_t initialize_session;
    void* initialize_session_ctx;
} trezor_wallet_adapter_config_t;

trezor_session_t trezor_wallet_adapter_session(const trezor_wallet_adapter_config_t* config);

#endif /* TREZOR_WALLET_ADAPTER_H_ */
