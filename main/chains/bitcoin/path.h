#ifndef BITCOIN_PATH_H_
#define BITCOIN_PATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BITCOIN_TESTNET_SLIP44 1
#define BITCOIN_P2PKH_SPENDADDRESS 0
#define BITCOIN_P2WPKH_SPENDWITNESS 3
#define BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS 4

bool bitcoin_path_is_trezor_connect_state_testnet_p2pkh(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_testnet_p2pkh_account_public_node(const uint32_t* path, size_t path_len);

#endif /* BITCOIN_PATH_H_ */
