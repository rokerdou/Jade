#ifndef TREZOR_SESSION_H_
#define TREZOR_SESSION_H_

#include "bitcoin.h"
#include "ethereum.h"
#include "features.h"
#include "public_key.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN 2048
#define TREZOR_SESSION_MAX_RESPONSE_PAYLOAD_LEN 1024
#define TREZOR_SESSION_BITCOIN_ADDRESS_STRING_LEN BITCOIN_P2PKH_ADDRESS_MAX_LEN
#define TREZOR_SESSION_ETH_ADDRESS_STRING_LEN 43

typedef bool (*trezor_session_bitcoin_address_callback_t)(
    void* ctx, const trezor_bitcoin_get_address_t* request, char* address, size_t address_len);
typedef bool (*trezor_session_eth_address_callback_t)(
    void* ctx, const trezor_ethereum_get_address_t* request, char* address, size_t address_len);
typedef bool (*trezor_session_public_key_callback_t)(
    void* ctx, const trezor_public_key_request_t* request, trezor_public_key_response_t* response);
typedef bool (*trezor_session_eth_sign_tx_callback_t)(
    void* ctx, const ethereum_tx_preflight_request_t* request, ethereum_signature_t* signature);
typedef bool (*trezor_session_bool_callback_t)(void* ctx);
typedef bool (*trezor_session_initialize_callback_t)(void* ctx, const uint8_t* session_id, size_t session_id_len);

typedef struct {
    bool has_pending_local_unlock;
    bool has_pending_eth_signing;
    bool has_pending_btc_signing;
    uint16_t pending_request_type;
    uint8_t pending_request_payload[TREZOR_SESSION_MAX_REQUEST_PAYLOAD_LEN];
    size_t pending_request_payload_len;
    trezor_ethereum_signing_state_t pending_eth_signing;
    trezor_bitcoin_signing_state_t pending_btc_signing;
} trezor_session_state_t;

typedef struct {
    trezor_features_t features;
    trezor_session_state_t* state;
    trezor_session_initialize_callback_t initialize_session;
    void* initialize_session_ctx;
    trezor_session_bool_callback_t needs_local_unlock;
    void* needs_local_unlock_ctx;
    trezor_session_bool_callback_t perform_local_unlock;
    void* perform_local_unlock_ctx;
    trezor_session_bitcoin_address_callback_t get_bitcoin_address;
    void* get_bitcoin_address_ctx;
    trezor_session_eth_address_callback_t get_eth_address;
    void* get_eth_address_ctx;
    trezor_session_public_key_callback_t get_public_key;
    void* get_public_key_ctx;
    trezor_session_eth_sign_tx_callback_t sign_eth_tx;
    void* sign_eth_tx_ctx;
} trezor_session_t;

bool trezor_session_handle_payload(const trezor_session_t* session, uint16_t request_type,
    const uint8_t* request_payload, size_t request_payload_len, uint16_t* response_type, uint8_t* response_payload,
    size_t response_payload_len, size_t* response_payload_written);
bool trezor_session_handle_wire(const trezor_session_t* session, const uint8_t* request_chunks,
    size_t request_chunks_len, uint8_t* response_chunks, size_t response_chunks_len, size_t* response_chunks_written);

#endif /* TREZOR_SESSION_H_ */
