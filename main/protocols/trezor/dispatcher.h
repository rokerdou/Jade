#ifndef TREZOR_DISPATCHER_H_
#define TREZOR_DISPATCHER_H_

#include "messages.h"

#include <stdbool.h>
#include <stdint.h>

bool trezor_dispatcher_message_allowed(uint32_t message_type);
bool trezor_dispatcher_message_sensitive_or_unsupported(uint32_t message_type);

#endif /* TREZOR_DISPATCHER_H_ */
