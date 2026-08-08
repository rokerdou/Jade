#ifndef AMALGAMATED_BUILD
#include "wallet.h"

#include "address.h"
#include "path.h"

#include <wally_crypto.h>

bool bitcoin_wallet_p2pkh_testnet_address_from_path(
    const wallet_core_path_t* const path, char* const output, const size_t output_len)
{
    if (!path || !bitcoin_path_is_trezor_connect_state_testnet_p2pkh(path->parts, path->len) || !output) {
        return false;
    }

    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    const bool ok = wallet_core_get_public_key(path, WALLET_CORE_PUBKEY_COMPRESSED, pubkey, sizeof(pubkey))
        && bitcoin_p2pkh_testnet_address_from_compressed_pubkey(pubkey, sizeof(pubkey), output, output_len);
    wally_bzero(pubkey, sizeof(pubkey));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
