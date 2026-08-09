#ifndef AMALGAMATED_BUILD
#include "auth_bridge.h"

#ifdef CONFIG_TREZOR_USB_HID

#include "trace.h"

#include "../../process.h"
#include "../../process/auth_user.h"
#include "../../wallet_core/wallet_core.h"

bool trezor_auth_bridge_wallet_ready(void)
{
    return wallet_core_is_ready();
}

bool trezor_auth_bridge_needs_local_unlock(void* ctx)
{
    (void)ctx;
    return wallet_core_is_initialized() && !wallet_core_is_ready() && !wallet_core_is_unlocked();
}

bool trezor_auth_bridge_perform_local_unlock(void* ctx)
{
    (void)ctx;
    if (!wallet_core_is_initialized()) {
        trezor_trace_set_stage("unlock:not_init");
        return false;
    }
    if (wallet_core_is_ready() || wallet_core_is_unlocked()) {
        trezor_trace_set_stage("unlock:already_ready");
        return wallet_core_is_ready();
    }

    trezor_trace_set_stage("unlock:pin_ui");
    const bool auth_ok = auth_user_unlock_wallet_with_pin(SOURCE_SERIAL);
    const bool ready = wallet_core_is_ready();
    trezor_trace_set_note("unlock auth=%u ready=%u", auth_ok ? 1U : 0U, ready ? 1U : 0U);
    trezor_trace_set_stage(auth_ok && ready ? "unlock:pin_ok" : "unlock:pin_fail");
    return auth_ok && ready;
}

#endif /* CONFIG_TREZOR_USB_HID */
#endif /* AMALGAMATED_BUILD */
