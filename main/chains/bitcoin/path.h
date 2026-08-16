#ifndef BITCOIN_PATH_H_
#define BITCOIN_PATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BITCOIN_MAINNET_SLIP44 0
#define BITCOIN_TESTNET_SLIP44 1
#define BITCOIN_P2PKH_SPENDADDRESS 0
#define BITCOIN_MULTISIG_SPENDMULTISIG 1
#define BITCOIN_P2WPKH_SPENDWITNESS 3
#define BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS 4

typedef enum {
    BITCOIN_MULTISIG_PATH_P2SH = 0,
    BITCOIN_MULTISIG_PATH_P2SH_P2WSH = 1,
    BITCOIN_MULTISIG_PATH_P2WSH = 2,
} bitcoin_multisig_path_type_t;

bool bitcoin_path_is_trezor_connect_state_testnet_p2pkh(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_testnet_p2pkh_account_public_node(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_p2pkh_account_public_node(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2wpkh_account_public_node(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2sh_p2wpkh_account_public_node(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_legacy_multisig_account_public_node(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_p2sh_p2wsh_account_public_node(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2wsh_account_public_node(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_testnet_p2wpkh_signing(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_testnet_p2sh_p2wpkh_signing(const uint32_t* path, size_t path_len);
bool bitcoin_path_is_p2pkh_signing(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2wpkh_signing(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2sh_p2wpkh_signing(const uint32_t* path, size_t path_len, bool testnet);
bool bitcoin_path_is_p2pkh_change(const uint32_t* path, size_t path_len, bool testnet, uint32_t account);
bool bitcoin_path_is_p2wpkh_change(const uint32_t* path, size_t path_len, bool testnet, uint32_t account);
bool bitcoin_path_is_p2sh_p2wpkh_change(const uint32_t* path, size_t path_len, bool testnet, uint32_t account);
bool bitcoin_path_is_multisig_signing(
    const uint32_t* path, size_t path_len, bool testnet, bitcoin_multisig_path_type_t path_type);
bool bitcoin_path_is_multisig_change(
    const uint32_t* path, size_t path_len, bool testnet, bitcoin_multisig_path_type_t path_type);
bool bitcoin_path_multisig_wallet_matches(
    const uint32_t* first, size_t first_len, const uint32_t* second, size_t second_len);
bool bitcoin_path_is_multisig_change_for_input(const uint32_t* input, size_t input_len, const uint32_t* change,
    size_t change_len, bool testnet, bitcoin_multisig_path_type_t path_type);

#endif /* BITCOIN_PATH_H_ */
