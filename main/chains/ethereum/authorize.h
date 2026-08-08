#ifndef ETHEREUM_AUTHORIZE_H_
#define ETHEREUM_AUTHORIZE_H_

#include <stdbool.h>

#include "../authorization.h"
#include "tx.h"

/*
 * Build and display an on-device confirmation summary for an Ethereum request.
 *
 * This function deliberately does not sign a caller-provided digest. The digest
 * must later be produced inside a firmware parser/encoder path that is bound to
 * the same normalized request the user confirmed on the hardware screen.
 */
bool ethereum_authorize_tx(const ethereum_tx_preflight_request_t* request, chain_authorization_t* authorization);

#endif /* ETHEREUM_AUTHORIZE_H_ */
