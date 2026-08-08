#ifndef ETHEREUM_DIGEST_H_
#define ETHEREUM_DIGEST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../authorization.h"
#include "tx.h"

#define ETHEREUM_TX_SIGNING_HASH_LEN 32
#define ETHEREUM_TX_MAX_SIGNING_PAYLOAD_LEN (ETHEREUM_TX_MAX_PREFLIGHT_DATA_LEN + 256)

bool ethereum_tx_signing_payload(
    const ethereum_tx_preflight_request_t* request, uint8_t* output, size_t output_len, size_t* written);
bool ethereum_tx_signing_hash(const ethereum_tx_preflight_request_t* request, uint8_t* output, size_t output_len);
bool ethereum_tx_build_authorized_digest(const ethereum_tx_preflight_request_t* request,
    const chain_authorization_t* authorization, chain_authorized_digest_t* output);

#endif /* ETHEREUM_DIGEST_H_ */
