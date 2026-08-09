#ifndef TREZOR_AUTH_BRIDGE_H_
#define TREZOR_AUTH_BRIDGE_H_

#include <stdbool.h>

bool trezor_auth_bridge_wallet_ready(void);
bool trezor_auth_bridge_needs_local_unlock(void* ctx);
bool trezor_auth_bridge_perform_local_unlock(void* ctx);

#endif /* TREZOR_AUTH_BRIDGE_H_ */
