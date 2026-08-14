#ifndef TREZOR_BITCOIN_SCRIPT_POLICY_H_
#define TREZOR_BITCOIN_SCRIPT_POLICY_H_

#include "policy.h"
#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool trezor_bitcoin_script_policy_prevout_matches_input(const trezor_bitcoin_tx_input_t* input,
    trezor_bitcoin_coin_t coin, const uint8_t* script_pubkey, size_t script_pubkey_len);

#endif /* TREZOR_BITCOIN_SCRIPT_POLICY_H_ */
