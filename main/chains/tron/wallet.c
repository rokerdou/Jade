#ifndef AMALGAMATED_BUILD
#include "wallet.h"

#include "address.h"
#include "path.h"

#include <wally_crypto.h>

bool tron_wallet_address_from_path(const wallet_core_path_t* const path, uint8_t* const output, const size_t output_len)
{
    if (!path || !tron_path_is_supported(path->parts, path->len) || !output || output_len != TRON_ADDRESS_LEN) {
        return false;
    }

    uint8_t pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    if (!wallet_core_get_public_key(path, WALLET_CORE_PUBKEY_UNCOMPRESSED, pubkey, sizeof(pubkey))) {
        return false;
    }

    const bool ok = tron_address_from_uncompressed_pubkey(pubkey, sizeof(pubkey), output, output_len);
    wally_bzero(pubkey, sizeof(pubkey));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
