#ifndef ETHEREUM_WALLET_H_
#define ETHEREUM_WALLET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../wallet_core/wallet_core.h"

bool ethereum_wallet_address_from_path(const wallet_core_path_t* path, uint8_t* output, size_t output_len);

#endif /* ETHEREUM_WALLET_H_ */
