#ifndef TREZOR_ETHEREUM_SAFE_NORMALIZER_H_
#define TREZOR_ETHEREUM_SAFE_NORMALIZER_H_

#include "../../../chains/ethereum/safe_tx.h"
#include "protocol.h"

#include <stdbool.h>
#include <stdint.h>

bool trezor_ethereum_safe_typed_hash_bind(const trezor_ethereum_sign_typed_hash_t* typed_hash,
    const ethereum_safe_tx_t* safe_tx, uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN],
    ethereum_safe_tx_summary_t* summary);

#endif /* TREZOR_ETHEREUM_SAFE_NORMALIZER_H_ */
