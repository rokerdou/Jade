#ifndef AMALGAMATED_BUILD
#include "public_node.h"

#include "../../../chains/bitcoin/path.h"

#include <string.h>
#include <wally_bip32.h>

#define TREZOR_XPUB_MAINNET_P2SH_P2WPKH 0x049D7CB2U
#define TREZOR_XPUB_MAINNET_P2WPKH 0x04B24746U
#define TREZOR_XPUB_MAINNET_P2SH_P2WSH 0x0295B43FU
#define TREZOR_XPUB_MAINNET_P2WSH 0x02AA7ED3U
#define TREZOR_XPUB_TESTNET_P2SH_P2WPKH 0x044A5262U
#define TREZOR_XPUB_TESTNET_P2WPKH 0x045F1CF6U
#define TREZOR_XPUB_TESTNET_P2SH_P2WSH 0x024289EFU
#define TREZOR_XPUB_TESTNET_P2WSH 0x02575483U

typedef enum {
    TREZOR_BITCOIN_PUBLIC_NODE_P2PKH,
    TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WPKH,
    TREZOR_BITCOIN_PUBLIC_NODE_P2WPKH,
    TREZOR_BITCOIN_PUBLIC_NODE_LEGACY_MULTISIG,
    TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WSH,
    TREZOR_BITCOIN_PUBLIC_NODE_P2WSH,
} trezor_bitcoin_public_node_kind_t;

static bool trezor_bitcoin_public_node_allows_script(
    const trezor_public_key_request_t* const request, const uint32_t inferred_script_type)
{
    return !request->has_script_type || request->script_type == inferred_script_type
        || request->script_type == BITCOIN_P2PKH_SPENDADDRESS
        || (inferred_script_type == BITCOIN_MULTISIG_SPENDMULTISIG
            && request->script_type == BITCOIN_MULTISIG_SPENDMULTISIG);
}

static bool trezor_bitcoin_public_node_script_type(
    const trezor_public_key_request_t* const request, const bool testnet, trezor_bitcoin_public_node_kind_t* const kind)
{
    if (!request || !kind) {
        return false;
    }

    if (bitcoin_path_is_p2pkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_P2PKH_SPENDADDRESS)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_P2PKH;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        /* GetPublicKey defaults script_type to SPENDADDRESS; Sparrow/lark serializes that default while still
         * expecting account-path based BIP84 xpub magic. Limit this compatibility to public account-node export. */
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_P2WPKH_SPENDWITNESS)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_P2WPKH;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2sh_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        /* Same compatibility rule for BIP49 account xpub import. Transaction signing remains script-policy strict. */
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WPKH;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_legacy_multisig_account_public_node(request->address_n, request->address_n_len)) {
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_MULTISIG_SPENDMULTISIG)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_LEGACY_MULTISIG;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2sh_p2wsh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_MULTISIG_SPENDMULTISIG)
            || (request->has_script_type && request->script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WSH;
            return true;
        }
        return false;
    }
    if (bitcoin_path_is_p2wsh_account_public_node(request->address_n, request->address_n_len, testnet)) {
        if (trezor_bitcoin_public_node_allows_script(request, BITCOIN_MULTISIG_SPENDMULTISIG)
            || (request->has_script_type && request->script_type == BITCOIN_P2WPKH_SPENDWITNESS)) {
            *kind = TREZOR_BITCOIN_PUBLIC_NODE_P2WSH;
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
    trezor_bitcoin_public_node_kind_t kind = TREZOR_BITCOIN_PUBLIC_NODE_P2PKH;
    if (!trezor_bitcoin_public_node_script_type(request, testnet, &kind)) {
        return false;
    }

    const bool ignore_magic = request->has_ignore_xpub_magic && request->ignore_xpub_magic;
    if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2PKH || kind == TREZOR_BITCOIN_PUBLIC_NODE_LEGACY_MULTISIG) {
        if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2PKH
            && !bitcoin_path_is_p2pkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        if (kind == TREZOR_BITCOIN_PUBLIC_NODE_LEGACY_MULTISIG
            && !bitcoin_path_is_legacy_multisig_account_public_node(request->address_n, request->address_n_len)) {
            return false;
        }
        *version = testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC;
        return true;
    }
    if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2WPKH) {
        if (!bitcoin_path_is_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2WPKH : TREZOR_XPUB_MAINNET_P2WPKH);
        return true;
    }
    if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WPKH) {
        if (!bitcoin_path_is_p2sh_p2wpkh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2SH_P2WPKH : TREZOR_XPUB_MAINNET_P2SH_P2WPKH);
        return true;
    }
    if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2SH_P2WSH) {
        if (!bitcoin_path_is_p2sh_p2wsh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2SH_P2WSH : TREZOR_XPUB_MAINNET_P2SH_P2WSH);
        return true;
    }
    if (kind == TREZOR_BITCOIN_PUBLIC_NODE_P2WSH) {
        if (!bitcoin_path_is_p2wsh_account_public_node(request->address_n, request->address_n_len, testnet)) {
            return false;
        }
        *version = ignore_magic ? (testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC)
                                : (testnet ? TREZOR_XPUB_TESTNET_P2WSH : TREZOR_XPUB_MAINNET_P2WSH);
        return true;
    }
    return false;
}
#endif /* AMALGAMATED_BUILD */
