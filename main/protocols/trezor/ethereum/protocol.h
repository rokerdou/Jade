#ifndef TREZOR_ETHEREUM_PROTOCOL_H_
#define TREZOR_ETHEREUM_PROTOCOL_H_

#include "../../../chains/ethereum/sign.h"
#include "../../../chains/ethereum/tx.h"
#include "../../../wallet_core/wallet_core.h"
#include "definitions.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_ETHEREUM_MAX_TX_CHUNK_LEN 1024

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    bool show_display;
    bool has_show_display;
    bool chunkify;
    bool has_chunkify;
} trezor_ethereum_get_address_t;

typedef struct {
    uint32_t address_n[WALLET_CORE_MAX_PATH_LEN];
    size_t address_n_len;
    ethereum_tx_type_t tx_type;
    uint64_t chain_id;
    uint64_t nonce;
    uint64_t gas_limit;
    uint64_t gas_price;
    uint64_t max_priority_fee_per_gas;
    uint64_t max_fee_per_gas;
    bool has_to;
    uint8_t to[ETHEREUM_ADDRESS_LEN];
    uint8_t value[EVM_ABI_WORD_LEN];
    size_t value_len;
    uint8_t data[ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN];
    size_t data_len;
    size_t data_received;
    size_t next_chunk_len;
    trezor_ethereum_definitions_t definitions;
} trezor_ethereum_signing_state_t;

bool trezor_ethereum_get_address_decode(
    const uint8_t* payload, size_t payload_len, trezor_ethereum_get_address_t* output);
bool trezor_ethereum_address_encode(const char* address, uint8_t* output, size_t output_len, size_t* written);
bool trezor_ethereum_sign_tx_init(trezor_ethereum_signing_state_t* state, uint16_t message_type,
    const uint8_t* payload, size_t payload_len);
bool trezor_ethereum_tx_ack_apply(
    trezor_ethereum_signing_state_t* state, const uint8_t* payload, size_t payload_len);
bool trezor_ethereum_signing_state_ready(const trezor_ethereum_signing_state_t* state);
bool trezor_ethereum_signing_state_to_request(
    const trezor_ethereum_signing_state_t* state, ethereum_tx_preflight_request_t* request);
bool trezor_ethereum_tx_request_encode_data(size_t data_length, uint8_t* output, size_t output_len, size_t* written);
bool trezor_ethereum_tx_request_encode_signature(
    const ethereum_signature_t* signature, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_ETHEREUM_PROTOCOL_H_ */
