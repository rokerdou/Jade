#ifndef BITCOIN_CONFIRM_H_
#define BITCOIN_CONFIRM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../confirm_summary.h"
#include "address.h"

typedef struct {
    uint32_t path[CHAIN_CONFIRM_MAX_PATH_LEN];
    size_t path_len;
    char to[BITCOIN_ADDRESS_MAX_LEN];
    uint64_t amount;
    uint64_t fee;
} bitcoin_confirm_request_t;

bool bitcoin_confirm_summary_from_request(const bitcoin_confirm_request_t* request, chain_confirm_summary_t* summary);

#endif /* BITCOIN_CONFIRM_H_ */
