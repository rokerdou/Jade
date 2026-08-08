#ifndef AMALGAMATED_BUILD
#include "path.h"

#include "../path.h"

static bool tron_path_hardened_in_range(const uint32_t value, const uint32_t max_unhardened)
{
    return chain_path_is_hardened(value) && chain_path_unharden(value) <= max_unhardened;
}

static bool tron_path_nonhardened_in_range(const uint32_t value, const uint32_t max_value)
{
    return !chain_path_is_hardened(value) && value <= max_value;
}

tron_path_kind_t tron_path_classify(const uint32_t* const path, const size_t path_len)
{
    if (!path || path_len != 5 || path[0] != chain_path_harden(44) || path[1] != chain_path_harden(TRON_SLIP44)
        || !tron_path_hardened_in_range(path[2], CHAIN_PATH_MAX_ACCOUNT)
        || !tron_path_nonhardened_in_range(path[4], CHAIN_PATH_MAX_ADDRESS_INDEX)) {
        return TRON_PATH_UNSUPPORTED;
    }

    if (path[3] == 0) {
        return TRON_PATH_BIP44_EXTERNAL;
    }
    if (path[3] == 1) {
        return TRON_PATH_BIP44_CHANGE;
    }

    return TRON_PATH_UNSUPPORTED;
}

bool tron_path_is_supported(const uint32_t* const path, const size_t path_len)
{
    return tron_path_classify(path, path_len) != TRON_PATH_UNSUPPORTED;
}

bool tron_path_is_standard_external(const uint32_t* const path, const size_t path_len)
{
    return tron_path_classify(path, path_len) == TRON_PATH_BIP44_EXTERNAL;
}
#endif /* AMALGAMATED_BUILD */
