#ifndef WALLET_ENTROPY_H_
#define WALLET_ENTROPY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WALLET_ENTROPY_256_LEN 32U
#define WALLET_ENTROPY_DICE_MAX_ROLLS 99U
#define WALLET_ENTROPY_DICE_RECOMMENDED_ROLLS 50U

bool wallet_entropy_system_256(uint8_t entropy[WALLET_ENTROPY_256_LEN]);
bool wallet_entropy_dice_hash(uint8_t user_entropy[WALLET_ENTROPY_256_LEN], const uint8_t* dice_rolls, size_t roll_count);
bool wallet_entropy_standard(
    uint8_t final_entropy[WALLET_ENTROPY_256_LEN], const uint8_t system_entropy[WALLET_ENTROPY_256_LEN]);
bool wallet_entropy_enhanced(uint8_t final_entropy[WALLET_ENTROPY_256_LEN],
    const uint8_t system_entropy[WALLET_ENTROPY_256_LEN], const uint8_t* dice_rolls, size_t roll_count);

#endif /* WALLET_ENTROPY_H_ */
