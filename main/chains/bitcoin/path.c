#ifndef AMALGAMATED_BUILD
#include "path.h"

#include "../path.h"

bool bitcoin_path_is_trezor_connect_state_testnet_p2pkh(const uint32_t* const path, const size_t path_len)
{
    return path && path_len == 5 && path[0] == chain_path_harden(44)
        && path[1] == chain_path_harden(BITCOIN_TESTNET_SLIP44) && path[2] == chain_path_harden(0) && path[3] == 0
        && path[4] == 0;
}

bool bitcoin_path_is_testnet_p2pkh_account_public_node(const uint32_t* const path, const size_t path_len)
{
    return path && path_len == 3 && path[0] == chain_path_harden(44)
        && path[1] == chain_path_harden(BITCOIN_TESTNET_SLIP44) && (path[2] & 0x80000000U) != 0;
}

bool bitcoin_path_is_testnet_p2wpkh_signing(const uint32_t* const path, const size_t path_len)
{
    return path && path_len == 5 && path[0] == chain_path_harden(84)
        && path[1] == chain_path_harden(BITCOIN_TESTNET_SLIP44) && (path[2] & 0x80000000U) != 0 && path[3] == 0
        && path[4] <= 1000000U;
}
#endif /* AMALGAMATED_BUILD */
