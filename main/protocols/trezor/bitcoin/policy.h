#ifndef TREZOR_BITCOIN_POLICY_H_
#define TREZOR_BITCOIN_POLICY_H_

#include "protocol.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    TREZOR_BITCOIN_COIN_MAINNET = 0,
    TREZOR_BITCOIN_COIN_TESTNET = 1,
} trezor_bitcoin_coin_t;

bool trezor_bitcoin_coin_from_name(const char* name, trezor_bitcoin_coin_t* coin);
bool trezor_bitcoin_coin_is_testnet(trezor_bitcoin_coin_t coin);
const char* trezor_bitcoin_coin_segwit_hrp(trezor_bitcoin_coin_t coin);

bool trezor_bitcoin_policy_calculate_totals(trezor_bitcoin_signing_state_t* state);
bool trezor_bitcoin_policy_estimate_p2wpkh_fee_rate(trezor_bitcoin_signing_state_t* state);
bool trezor_bitcoin_policy_signing_coin(const trezor_bitcoin_signing_state_t* state, trezor_bitcoin_coin_t* coin);
bool trezor_bitcoin_policy_is_p2wpkh_basic(const trezor_bitcoin_signing_state_t* state);

#endif /* TREZOR_BITCOIN_POLICY_H_ */
