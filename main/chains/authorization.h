#ifndef CHAIN_AUTHORIZATION_H_
#define CHAIN_AUTHORIZATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../wallet_core/wallet_core.h"
#include "confirm_summary.h"

#define CHAIN_AUTHORIZATION_BINDING_LEN 32
#define CHAIN_AUTHORIZED_DIGEST_LEN 32

typedef struct {
    wallet_core_path_t path;
    chain_confirm_summary_t summary;
} chain_authorization_t;

typedef struct {
    wallet_core_path_t path;
    chain_confirm_chain_t chain;
    uint8_t tx_digest[CHAIN_AUTHORIZED_DIGEST_LEN];
    uint8_t authorization_binding[CHAIN_AUTHORIZATION_BINDING_LEN];
    uint8_t signing_binding[CHAIN_AUTHORIZATION_BINDING_LEN];
} chain_authorized_digest_t;

bool chain_authorization_compute_binding(
    const chain_authorization_t* authorization, uint8_t* output, size_t output_len);
bool chain_authorized_digest_init(const chain_authorization_t* authorization, const uint8_t* tx_digest,
    size_t tx_digest_len, chain_authorized_digest_t* output);
bool chain_authorized_digest_matches_authorization(
    const chain_authorization_t* authorization, const chain_authorized_digest_t* authorized_digest);

#endif /* CHAIN_AUTHORIZATION_H_ */
