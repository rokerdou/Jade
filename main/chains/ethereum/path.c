#ifndef AMALGAMATED_BUILD
#include "path.h"

#include "../path.h"

static bool ethereum_path_hardened_in_range(const uint32_t value, const uint32_t max_unhardened)
{
    return chain_path_is_hardened(value) && chain_path_unharden(value) <= max_unhardened;
}

static bool ethereum_path_nonhardened_in_range(const uint32_t value, const uint32_t max_value)
{
    return !chain_path_is_hardened(value) && value <= max_value;
}

ethereum_path_kind_t ethereum_path_classify(const uint32_t* const path, const size_t path_len)
{
    if (!path || path_len < 3 || path[0] != chain_path_harden(44) || path[1] != chain_path_harden(ETHEREUM_SLIP44)) {
        return ETHEREUM_PATH_UNSUPPORTED;
    }

    if (path_len == 3 && ethereum_path_hardened_in_range(path[2], CHAIN_PATH_MAX_ACCOUNT)) {
        return ETHEREUM_PATH_SEP5;
    }

    if (path_len == 4 && path[2] == chain_path_harden(0)
        && ethereum_path_nonhardened_in_range(path[3], CHAIN_PATH_MAX_ACCOUNT)) {
        return ETHEREUM_PATH_LEDGER_LIVE_LEGACY;
    }

    if (path_len != 5) {
        return ETHEREUM_PATH_UNSUPPORTED;
    }

    if (path[2] == chain_path_harden(0) && path[3] == 0
        && ethereum_path_nonhardened_in_range(path[4], CHAIN_PATH_MAX_ACCOUNT)) {
        return ETHEREUM_PATH_BIP44_ACCOUNT;
    }

    if (ethereum_path_hardened_in_range(path[2], CHAIN_PATH_MAX_ACCOUNT) && (path[3] == 0 || path[3] == 1)
        && ethereum_path_nonhardened_in_range(path[4], CHAIN_PATH_MAX_ADDRESS_INDEX)) {
        return ETHEREUM_PATH_BIP44;
    }

    return ETHEREUM_PATH_UNSUPPORTED;
}

bool ethereum_path_is_supported(const uint32_t* const path, const size_t path_len)
{
    return ethereum_path_classify(path, path_len) != ETHEREUM_PATH_UNSUPPORTED;
}

bool ethereum_path_is_standard_external(const uint32_t* const path, const size_t path_len)
{
    const ethereum_path_kind_t kind = ethereum_path_classify(path, path_len);
    if (kind == ETHEREUM_PATH_BIP44_ACCOUNT) {
        return true;
    }
    return kind == ETHEREUM_PATH_BIP44 && path && path_len == 5 && path[3] == 0;
}

bool ethereum_path_is_public_key_export_supported(const uint32_t* const path, const size_t path_len)
{
    const ethereum_path_kind_t kind = ethereum_path_classify(path, path_len);
    if (kind == ETHEREUM_PATH_SEP5 || kind == ETHEREUM_PATH_LEDGER_LIVE_LEGACY) {
        return true;
    }

    return kind == ETHEREUM_PATH_BIP44_ACCOUNT && path && path_len == 5 && path[4] == 0;
}
#endif /* AMALGAMATED_BUILD */
