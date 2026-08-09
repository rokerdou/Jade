#ifndef TREZOR_BITCOIN_PREV_TX_VERIFIER_H_
#define TREZOR_BITCOIN_PREV_TX_VERIFIER_H_

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    struct wally_tx* tx;
    bool initialized;
    uint8_t expected_txid[SHA256_LEN];
    uint32_t inputs_count;
    uint32_t outputs_count;
    uint32_t prev_index;
    size_t inputs_seen;
    size_t outputs_seen;
    bool has_prevout;
    uint64_t prevout_amount;
    uint8_t prevout_script[TREZOR_BITCOIN_PREV_SCRIPT_MAX_LEN];
    size_t prevout_script_len;
} trezor_bitcoin_prev_tx_verifier_t;

void trezor_bitcoin_prev_tx_verifier_reset(trezor_bitcoin_prev_tx_verifier_t* verifier);
bool trezor_bitcoin_prev_tx_verifier_init(trezor_bitcoin_prev_tx_verifier_t* verifier,
    const trezor_bitcoin_transaction_t* meta, const uint8_t* expected_txid, size_t expected_txid_len,
    uint32_t prev_index);
bool trezor_bitcoin_prev_tx_verifier_apply_input(
    trezor_bitcoin_prev_tx_verifier_t* verifier, const trezor_bitcoin_prev_input_t* input);
bool trezor_bitcoin_prev_tx_verifier_apply_output(
    trezor_bitcoin_prev_tx_verifier_t* verifier, const trezor_bitcoin_prev_output_t* output);
bool trezor_bitcoin_prev_tx_verifier_finish(trezor_bitcoin_prev_tx_verifier_t* verifier, uint64_t* amount,
    uint8_t* script_pubkey, size_t script_pubkey_len, size_t* script_pubkey_written);

#endif /* TREZOR_BITCOIN_PREV_TX_VERIFIER_H_ */
