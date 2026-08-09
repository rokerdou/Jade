#ifndef TREZOR_ETHEREUM_NORMALIZER_H_
#define TREZOR_ETHEREUM_NORMALIZER_H_

#include "../../../chains/ethereum/tx.h"
#include "protocol.h"

#include <stdbool.h>

bool trezor_ethereum_signing_state_to_request(
    const trezor_ethereum_signing_state_t* state, ethereum_tx_preflight_request_t* request);

#endif /* TREZOR_ETHEREUM_NORMALIZER_H_ */
