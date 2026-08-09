#ifndef UI_CHAIN_CONFIRM_H_
#define UI_CHAIN_CONFIRM_H_

#include <stdbool.h>

#include "../chains/confirm_summary.h"

#define CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES 4U
#define CHAIN_CONFIRM_UI_HEX_LINE_CHARS 22U
#define CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX 24U
#define CHAIN_CONFIRM_UI_MAX_HEX_CHARS (2U + (2U * CHAIN_CONFIRM_MAX_BYTES))
#define CHAIN_CONFIRM_UI_MAX_HEX_LINES                                                                         \
    ((CHAIN_CONFIRM_UI_MAX_HEX_CHARS + CHAIN_CONFIRM_UI_HEX_LINE_CHARS - 1U) / CHAIN_CONFIRM_UI_HEX_LINE_CHARS)

_Static_assert(CHAIN_CONFIRM_UI_MAX_HEX_LINES <= CHAIN_CONFIRM_UI_MAX_MESSAGE_LINES,
    "chain confirmation hex fields must fit in Jade's message activity line limit");
_Static_assert(CHAIN_CONFIRM_UI_HEX_LINE_CHARS + 1U <= CHAIN_CONFIRM_UI_DISPLAY_LINE_MAX,
    "chain confirmation hex line buffer must include room for a terminator");

bool show_chain_confirm_summary_activity(const chain_confirm_summary_t* summary);

#endif /* UI_CHAIN_CONFIRM_H_ */
