#ifndef TREZOR_BITCOIN_MULTISIG_TX_H_
#define TREZOR_BITCOIN_MULTISIG_TX_H_

#include "protocol.h"

typedef struct {
    const trezor_bitcoin_multisig_policy_t* policy;
    const uint8_t* compact_signatures;
    size_t compact_signatures_len;
    size_t signatures_count;
} trezor_bitcoin_multisig_unlock_t;

bool trezor_bitcoin_multisig_build_hash(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_multisig_policy_t* const* policies, size_t policies_len, size_t input_index,
    wallet_core_path_t* path, uint8_t* digest, size_t digest_len);

bool trezor_bitcoin_multisig_build_signed_tx(const trezor_bitcoin_signing_state_t* state,
    const trezor_bitcoin_multisig_unlock_t* unlocks, size_t unlocks_len, uint8_t* serialized_tx,
    size_t serialized_tx_len, size_t* serialized_tx_written);

#endif /* TREZOR_BITCOIN_MULTISIG_TX_H_ */
