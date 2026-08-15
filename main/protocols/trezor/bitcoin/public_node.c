#ifndef AMALGAMATED_BUILD
#include "public_node.h"

#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_bip32.h>

#define TREZOR_XPUB_MAINNET_P2SH_P2WPKH 0x049D7CB2U
#define TREZOR_XPUB_MAINNET_P2WPKH 0x04B24746U
#define TREZOR_XPUB_TESTNET_P2SH_P2WPKH 0x044A5262U
#define TREZOR_XPUB_TESTNET_P2WPKH 0x045F1CF6U

static bool trezor_bitcoin_public_node_script_type(
    const trezor_public_key_request_t* const request, const bool testnet, uint32_t* const script_type)
{
    if (!request || !script_type) {
        return false;
    }

    if (bitcoin_path_is_p2pkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        if (!request->has_script_type || request->script_type == BITCOIN_P2PKH_SPENDADDRESS) {
            *script_type = BITCOIN_P2PKH_SPENDADDRESS;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        /* GetPublicKey defaults script_type to SPENDADDRESS; Sparrow/lark serializes that default while still
         * expecting account-path based BIP84 xpub magic. Limit this compatibility to public account-node export. */
        if (!request->has_script_type || request->script_type == BITCOIN_P2PKH_SPENDADDRESS
            || request->script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
            *script_type = BITCOIN_P2WPKH_SPENDWITNESS;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2sh_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        /* Same compatibility rule for BIP49 account xpub import. Transaction signing remains script-policy strict. */
        if (!request->has_script_type || request->script_type == BITCOIN_P2PKH_SPENDADDRESS
            || request->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
            *script_type = BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS;
            return true;
        }
        return false;
    }
    return false;
}

bool trezor_bitcoin_public_node_version(const trezor_public_key_request_t* const request, uint32_t* const version)
{
    if (!request || !version || request->kind != TREZOR_PUBLIC_KEY_REQUEST_GENERIC) {
        return false;
    }

    const char* const coin_name = request->has_coin_name ? request->coin_name : "Bitcoin";
    if (strcmp(coin_name, "Testnet") != 0 && strcmp(coin_name, "Bitcoin") != 0) {
        return false;
    }

    const bool testnet = strcmp(coin_name, "Testnet") == 0;
    uint32_t script_type = BITCOIN_P2PKH_SPENDADDRESS;
    if (!trezor_bitcoin_public_node_script_type(request, testnet, &script_type)) {
        return false;
    }

    const bool ignore_magic = request->has_ignore_xpub_magic && request->ignore_xpub_magic;
    if (script_type == BITCOIN_P2PKH_SPENDADDRESS) {
        if (!bitcoin_path_is_p2pkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC;
        return true;
    }
    if (script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        if (!bitcoin_path_is_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2WPKH : TREZOR_XPUB_MAINNET_P2WPKH);
        return true;
    }
    if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        if (!bitcoin_path_is_p2sh_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2SH_P2WPKH : TREZOR_XPUB_MAINNET_P2SH_P2WPKH);
        return true;
    }
    return false;
}
#endif /* AMALGAMATED_BUILD */
