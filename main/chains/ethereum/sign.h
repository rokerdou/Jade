#ifndef ETHEREUM_SIGN_H_
#define ETHEREUM_SIGN_H_

#include <stdbool.h>
#include <stdint.h>

#include "tx.h"

#define ETHEREUM_SIGNATURE_R_LEN 32
#define ETHEREUM_SIGNATURE_S_LEN 32

typedef struct {
    uint64_t v;
    uint8_t r[ETHEREUM_SIGNATURE_R_LEN];
    uint8_t s[ETHEREUM_SIGNATURE_S_LEN];
} ethereum_signature_t;

bool ethereum_sign_tx(const ethereum_tx_preflight_request_t* request, ethereum_signature_t* signature);

#endif /* ETHEREUM_SIGN_H_ */
