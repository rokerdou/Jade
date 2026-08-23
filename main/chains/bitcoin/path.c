#ifndef AMALGAMATED_BUILD
#include "path.h"

#include "../path.h"

#include <string.h>

bool bitcoin_path_is_trezor_connect_state_testnet_p2pkh(const uint32_t* const path, const size_t path_len)
{
    return path && path_len == 5 && path[0] == chain_path_harden(44)
        && path[1] == chain_path_harden(BITCOIN_TESTNET_SLIP44) && path[2] == chain_path_harden(0) && path[3] == 0
        && path[4] == 0;
}

bool bitcoin_path_is_testnet_p2pkh_account_public_node(const uint32_t* const path, const size_t path_len)
{
    return bitcoin_path_is_p2pkh_account_public_node(path, path_len, true);
}

static bool bitcoin_path_is_account_public_node(
    const uint32_t* const path, const size_t path_len, const uint32_t purpose, const bool testnet)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 3 && path[0] == chain_path_harden(purpose) && path[1] == chain_path_harden(slip44)
        && (path[2] & 0x80000000U) != 0;
}

bool bitcoin_path_is_p2pkh_account_public_node(
    const uint32_t* const path, const size_t path_len, const bool testnet)
{
    return bitcoin_path_is_account_public_node(path, path_len, 44, testnet);
}

bool bitcoin_path_is_p2wpkh_account_public_node(
    const uint32_t* const path, const size_t path_len, const bool testnet)
{
    return bitcoin_path_is_account_public_node(path, path_len, 84, testnet);
}

bool bitcoin_path_is_p2sh_p2wpkh_account_public_node(
    const uint32_t* const path, const size_t path_len, const bool testnet)
{
    return bitcoin_path_is_account_public_node(path, path_len, 49, testnet);
}

bool bitcoin_path_is_legacy_multisig_account_public_node(const uint32_t* const path, const size_t path_len)
{
    return path && path_len == 1 && path[0] == chain_path_harden(45);
}

static bool bitcoin_path_is_bip48_account_public_node(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t script_type)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 4 && path[0] == chain_path_harden(48) && path[1] == chain_path_harden(slip44)
        && (path[2] & 0x80000000U) != 0 && path[3] == chain_path_harden(script_type);
}

bool bitcoin_path_is_p2sh_p2wsh_account_public_node(
    const uint32_t* const path, const size_t path_len, const bool testnet)
{
    return bitcoin_path_is_bip48_account_public_node(path, path_len, testnet, 1);
}

bool bitcoin_path_is_p2wsh_account_public_node(const uint32_t* const path, const size_t path_len, const bool testnet)
{
    return bitcoin_path_is_bip48_account_public_node(path, path_len, testnet, 2);
}

bool bitcoin_path_is_testnet_p2wpkh_signing(const uint32_t* const path, const size_t path_len)
{
    return bitcoin_path_is_p2wpkh_signing(path, path_len, true);
}

bool bitcoin_path_is_testnet_p2sh_p2wpkh_signing(const uint32_t* const path, const size_t path_len)
{
    return bitcoin_path_is_p2sh_p2wpkh_signing(path, path_len, true);
}

bool bitcoin_path_is_p2pkh_signing(const uint32_t* const path, const size_t path_len, const bool testnet)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(44) && path[1] == chain_path_harden(slip44)
        && (path[2] & 0x80000000U) != 0 && path[3] == 0 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2wpkh_signing(const uint32_t* const path, const size_t path_len, const bool testnet)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(84) && path[1] == chain_path_harden(slip44)
        && (path[2] & 0x80000000U) != 0 && path[3] == 0 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2sh_p2wpkh_signing(const uint32_t* const path, const size_t path_len, const bool testnet)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(49) && path[1] == chain_path_harden(slip44)
        && (path[2] & 0x80000000U) != 0 && path[3] == 0 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2pkh_change(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(44) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] == 1 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2pkh_internal(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(44) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] <= 1 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2wpkh_change(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(84) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] == 1 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2wpkh_internal(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(84) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] <= 1 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2sh_p2wpkh_change(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(49) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] == 1 && path[4] <= 1000000U;
}

bool bitcoin_path_is_p2sh_p2wpkh_internal(
    const uint32_t* const path, const size_t path_len, const bool testnet, const uint32_t account)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 5 && path[0] == chain_path_harden(49) && path[1] == chain_path_harden(slip44)
        && path[2] == account && path[3] <= 1 && path[4] <= 1000000U;
}

static bool bitcoin_path_is_bip45_multisig(
    const uint32_t* const path, const size_t path_len, const bitcoin_multisig_path_type_t path_type)
{
    return path && path_type == BITCOIN_MULTISIG_PATH_P2SH && path_len == 4 && path[0] == chain_path_harden(45)
        && (path[1] & 0x80000000U) == 0 && path[1] <= 1000000U && path[2] <= 1U && path[3] <= 1000000U;
}

static bool bitcoin_path_is_bip48_multisig(
    const uint32_t* const path, const size_t path_len, const bool testnet, const bitcoin_multisig_path_type_t path_type)
{
    const uint32_t slip44 = testnet ? BITCOIN_TESTNET_SLIP44 : BITCOIN_MAINNET_SLIP44;
    return path && path_len == 6 && path_type <= BITCOIN_MULTISIG_PATH_P2WSH && path[0] == chain_path_harden(48)
        && path[1] == chain_path_harden(slip44) && (path[2] & 0x80000000U) != 0
        && path[3] == chain_path_harden((uint32_t)path_type) && path[4] <= 1U && path[5] <= 1000000U;
}

bool bitcoin_path_is_multisig_signing(
    const uint32_t* const path, const size_t path_len, const bool testnet, const bitcoin_multisig_path_type_t path_type)
{
    return bitcoin_path_is_bip45_multisig(path, path_len, path_type)
        || bitcoin_path_is_bip48_multisig(path, path_len, testnet, path_type);
}

bool bitcoin_path_is_multisig_change(
    const uint32_t* const path, const size_t path_len, const bool testnet, const bitcoin_multisig_path_type_t path_type)
{
    return bitcoin_path_is_multisig_signing(path, path_len, testnet, path_type) && path_len >= 2
        && path[path_len - 2U] == 1U;
}

bool bitcoin_path_multisig_wallet_matches(
    const uint32_t* const first, const size_t first_len, const uint32_t* const second, const size_t second_len)
{
    return first && second && first_len > 2 && first_len == second_len
        && memcmp(first, second, (first_len - 2U) * sizeof(first[0])) == 0;
}

bool bitcoin_path_is_multisig_change_for_input(const uint32_t* const input, const size_t input_len,
    const uint32_t* const change, const size_t change_len, const bool testnet,
    const bitcoin_multisig_path_type_t path_type)
{
    return bitcoin_path_is_multisig_signing(input, input_len, testnet, path_type)
        && bitcoin_path_is_multisig_change(change, change_len, testnet, path_type)
        && bitcoin_path_multisig_wallet_matches(input, input_len, change, change_len);
}
#endif /* AMALGAMATED_BUILD */
