#ifndef AUTH_USER_H_
#define AUTH_USER_H_

#include "../process.h"

#include <stdbool.h>

bool auth_user_save_wallet_with_pin(jade_msg_source_t source);
bool auth_user_unlock_wallet_with_pin(jade_msg_source_t source);

#endif /* AUTH_USER_H_ */
