#ifndef BITCOIN_WALLET_H_
#define BITCOIN_WALLET_H_

#include "../../wallet_core/wallet_core.h"

#include <stdbool.h>
#include <stddef.h>

bool bitcoin_wallet_p2pkh_testnet_address_from_path(
    const wallet_core_path_t* path, char* output, size_t output_len);
bool bitcoin_wallet_p2wpkh_testnet_address_from_path(
    const wallet_core_path_t* path, char* output, size_t output_len);
bool bitcoin_wallet_p2sh_p2wpkh_testnet_address_from_path(
    const wallet_core_path_t* path, char* output, size_t output_len);

#endif /* BITCOIN_WALLET_H_ */
