#ifndef TRON_AUTHORIZE_H_
#define TRON_AUTHORIZE_H_

#include <stdbool.h>

#include "../authorization.h"
#include "tx.h"

/*
 * Build and display an on-device confirmation summary for a TRON request.
 *
 * This function derives the signer address from the hardware wallet path and
 * requires it to match the transaction owner before the UI confirmation flow.
 */
bool tron_authorize_tx(const tron_tx_preflight_request_t* request, chain_authorization_t* authorization);

#endif /* TRON_AUTHORIZE_H_ */
