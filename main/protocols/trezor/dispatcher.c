#ifndef AMALGAMATED_BUILD
#include "dispatcher.h"

bool trezor_dispatcher_message_allowed(const uint32_t message_type)
{
    return message_type == TREZOR_MSG_INITIALIZE || message_type == TREZOR_MSG_GET_FEATURES
        || message_type == TREZOR_MSG_CANCEL || message_type == TREZOR_MSG_END_SESSION
        || message_type == TREZOR_MSG_APPLY_FLAGS || message_type == TREZOR_MSG_BUTTON_ACK
        || message_type == TREZOR_MSG_GET_ENTROPY || message_type == TREZOR_MSG_GET_ADDRESS
        || message_type == TREZOR_MSG_SIGN_TX || message_type == TREZOR_MSG_TX_ACK
        || message_type == TREZOR_MSG_ETHEREUM_GET_ADDRESS || message_type == TREZOR_MSG_GET_PUBLIC_KEY
        || message_type == TREZOR_MSG_ETHEREUM_GET_PUBLIC_KEY || message_type == TREZOR_MSG_ETHEREUM_SIGN_TX
        || message_type == TREZOR_MSG_ETHEREUM_SIGN_TX_EIP1559 || message_type == TREZOR_MSG_ETHEREUM_TX_ACK
        || message_type == TREZOR_MSG_ETHEREUM_SIGN_TYPED_HASH || message_type == TREZOR_MSG_ETHEREUM_GNOSIS_SAFE_TX_ACK
        || message_type == TREZOR_MSG_ONEKEY_SIGN_PSBT;
}

bool trezor_dispatcher_message_sensitive_or_unsupported(const uint32_t message_type)
{
    if (trezor_dispatcher_message_allowed(message_type)) {
        return false;
    }

    switch (message_type) {
    case TREZOR_MSG_LOAD_DEVICE:
    case TREZOR_MSG_RESET_DEVICE:
    case TREZOR_MSG_TX_ACK_PAYMENT_REQUEST:
    case TREZOR_MSG_CIPHER_KEY_VALUE:
    case TREZOR_MSG_BACKUP_DEVICE:
    case TREZOR_MSG_SIGN_MESSAGE:
    case TREZOR_MSG_PASSPHRASE_ACK:
    case TREZOR_MSG_RECOVERY_DEVICE:
    case TREZOR_MSG_SIGN_IDENTITY:
    case TREZOR_MSG_GET_ECDH_SESSION_KEY:
    case TREZOR_MSG_UNLOCK_PATH:
        return true;
    default:
        return true;
    }
}
#endif /* AMALGAMATED_BUILD */
