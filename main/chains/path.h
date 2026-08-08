#ifndef CHAIN_PATH_H_
#define CHAIN_PATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CHAIN_PATH_HARDENED 0x80000000UL
#define CHAIN_PATH_MAX_ACCOUNT 100UL
#define CHAIN_PATH_MAX_ADDRESS_INDEX 1000000UL

static inline bool chain_path_is_hardened(const uint32_t value) { return (value & CHAIN_PATH_HARDENED) != 0; }

static inline uint32_t chain_path_unharden(const uint32_t value) { return value & ~CHAIN_PATH_HARDENED; }

static inline uint32_t chain_path_harden(const uint32_t value) { return value | CHAIN_PATH_HARDENED; }

#endif /* CHAIN_PATH_H_ */
