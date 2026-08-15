#ifndef TREZOR_BITCOIN_PUBLIC_NODE_H_
#define TREZOR_BITCOIN_PUBLIC_NODE_H_

#include "../public_key.h"

#include <stdbool.h>
#include <stdint.h>

bool trezor_bitcoin_public_node_version(const trezor_public_key_request_t* request, uint32_t* version);

#endif /* TREZOR_BITCOIN_PUBLIC_NODE_H_ */
