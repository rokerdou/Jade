#ifndef ETHEREUM_CONFIRM_H_
#define ETHEREUM_CONFIRM_H_

#include <stdbool.h>

#include "../confirm_summary.h"
#include "tx.h"

bool ethereum_confirm_summary_from_preflight(const ethereum_tx_preflight_request_t* request,
    const ethereum_tx_preflight_result_t* result, chain_confirm_summary_t* summary);

#endif /* ETHEREUM_CONFIRM_H_ */
