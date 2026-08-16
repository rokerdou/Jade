#ifndef AMALGAMATED_BUILD
#include "safe_normalizer.h"

#include <string.h>
#include <wally_crypto.h>

bool trezor_ethereum_safe_typed_hash_bind(const trezor_ethereum_sign_typed_hash_t* const typed_hash,
    const ethereum_safe_tx_t* const safe_tx, uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN],
    ethereum_safe_tx_summary_t* const summary)
{
    if (!typed_hash || !safe_tx || !signing_hash || !summary || typed_hash->address_n_len == 0
        || !typed_hash->has_domain_separator_hash || !typed_hash->has_message_hash || typed_hash->has_encoded_network) {
        return false;
    }

    uint8_t domain_hash[KECCAK256_LEN];
    uint8_t message_hash[KECCAK256_LEN];
    uint8_t computed_signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN];
    wally_bzero(domain_hash, sizeof(domain_hash));
    wally_bzero(message_hash, sizeof(message_hash));
    wally_bzero(computed_signing_hash, sizeof(computed_signing_hash));
    wally_bzero(summary, sizeof(*summary));
    wally_bzero(signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN);

    const bool ok = ethereum_safe_tx_domain_separator_hash(safe_tx->chain_id, safe_tx->verifying_contract, domain_hash)
        && memcmp(domain_hash, typed_hash->domain_separator_hash, sizeof(domain_hash)) == 0
        && ethereum_safe_tx_message_hash(safe_tx, message_hash)
        && memcmp(message_hash, typed_hash->message_hash, sizeof(message_hash)) == 0
        && ethereum_safe_tx_signing_hash(safe_tx, computed_signing_hash)
        && ethereum_safe_tx_preflight(safe_tx, summary);

    if (ok) {
        memcpy(signing_hash, computed_signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN);
    } else {
        wally_bzero(summary, sizeof(*summary));
    }

    wally_bzero(domain_hash, sizeof(domain_hash));
    wally_bzero(message_hash, sizeof(message_hash));
    wally_bzero(computed_signing_hash, sizeof(computed_signing_hash));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
