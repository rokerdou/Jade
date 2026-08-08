#ifndef TRON_CONFIRM_H_
#define TRON_CONFIRM_H_

#include <stdbool.h>

#include "../confirm_summary.h"
#include "tx.h"

bool tron_confirm_summary_from_preflight(const tron_tx_preflight_request_t* request,
    const tron_tx_preflight_result_t* result, chain_confirm_summary_t* summary);

#endif /* TRON_CONFIRM_H_ */
