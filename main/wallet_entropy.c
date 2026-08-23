#ifndef AMALGAMATED_BUILD
#include "wallet_entropy.h"

#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "random.h"
#ifdef ESP_PLATFORM
#include "sensitive.h"
#endif

#include <string.h>
#include <wally_crypto.h>

static const uint8_t WALLET_DICE_DOMAIN[] = "WALLET_DICE_V1";

#ifdef ESP_PLATFORM
#define WALLET_ENTROPY_SENSITIVE_PUSH(addr, size) SENSITIVE_PUSH(addr, size)
#define WALLET_ENTROPY_SENSITIVE_POP(addr, size) \
    do {                                        \
        (void)(size);                           \
        SENSITIVE_POP(addr);                    \
    } while (0)
#else
#define WALLET_ENTROPY_SENSITIVE_PUSH(addr, size) \
    do {                                         \
        (void)(addr);                            \
        (void)(size);                            \
    } while (0)
#define WALLET_ENTROPY_SENSITIVE_POP(addr, size) JADE_WALLY_VERIFY(wally_bzero((addr), (size)))
#endif

bool wallet_entropy_system_256(uint8_t entropy[WALLET_ENTROPY_256_LEN])
{
    if (!entropy) {
        return false;
    }
#ifdef ESP_PLATFORM
    get_hardware_random(entropy, WALLET_ENTROPY_256_LEN);
    return true;
#else
    return false;
#endif
}

bool wallet_entropy_dice_hash(uint8_t user_entropy[WALLET_ENTROPY_256_LEN], const uint8_t* const dice_rolls,
    const size_t roll_count)
{
    if (!user_entropy || !dice_rolls || (roll_count != WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS
                                            && roll_count != WALLET_ENTROPY_DICE_MAX_ROLLS)) {
        return false;
    }
    for (size_t i = 0; i < roll_count; ++i) {
        if (dice_rolls[i] > 5U) {
            return false;
        }
    }

    uint8_t encoded[sizeof(WALLET_DICE_DOMAIN) - 1U + 1U + WALLET_ENTROPY_DICE_MAX_ROLLS];
    WALLET_ENTROPY_SENSITIVE_PUSH(encoded, sizeof(encoded));
    size_t pos = 0;
    memcpy(encoded + pos, WALLET_DICE_DOMAIN, sizeof(WALLET_DICE_DOMAIN) - 1U);
    pos += sizeof(WALLET_DICE_DOMAIN) - 1U;
    const uint8_t count = (uint8_t)roll_count;
    encoded[pos] = count;
    ++pos;
    memcpy(encoded + pos, dice_rolls, roll_count);
    pos += roll_count;
    JADE_ASSERT(pos <= sizeof(encoded));
    const bool ok = wally_sha256(encoded, pos, user_entropy, WALLET_ENTROPY_256_LEN) == WALLY_OK;
    WALLET_ENTROPY_SENSITIVE_POP(encoded, sizeof(encoded));
    return ok;
}

bool wallet_entropy_standard(
    uint8_t final_entropy[WALLET_ENTROPY_256_LEN], const uint8_t system_entropy[WALLET_ENTROPY_256_LEN])
{
    if (!final_entropy || !system_entropy) {
        return false;
    }
    memcpy(final_entropy, system_entropy, WALLET_ENTROPY_256_LEN);
    return true;
}

bool wallet_entropy_enhanced(uint8_t final_entropy[WALLET_ENTROPY_256_LEN],
    const uint8_t system_entropy[WALLET_ENTROPY_256_LEN], const uint8_t* const dice_rolls, const size_t roll_count)
{
    if (!final_entropy || !system_entropy || !dice_rolls) {
        return false;
    }

    uint8_t user_entropy[WALLET_ENTROPY_256_LEN];
    WALLET_ENTROPY_SENSITIVE_PUSH(user_entropy, sizeof(user_entropy));
    const bool ok = wallet_entropy_dice_hash(user_entropy, dice_rolls, roll_count);
    if (ok) {
        for (size_t i = 0; i < WALLET_ENTROPY_256_LEN; ++i) {
            final_entropy[i] = system_entropy[i] ^ user_entropy[i];
        }
    }
    WALLET_ENTROPY_SENSITIVE_POP(user_entropy, sizeof(user_entropy));
    return ok;
}
#endif /* AMALGAMATED_BUILD */
