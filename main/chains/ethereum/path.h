#ifndef ETHEREUM_PATH_H_
#define ETHEREUM_PATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ETHEREUM_SLIP44 60UL

typedef enum {
    ETHEREUM_PATH_UNSUPPORTED = 0,
    ETHEREUM_PATH_BIP44,
    ETHEREUM_PATH_BIP44_ACCOUNT,
    ETHEREUM_PATH_SEP5,
    ETHEREUM_PATH_LEDGER_LIVE_LEGACY,
} ethereum_path_kind_t;

ethereum_path_kind_t ethereum_path_classify(const uint32_t* path, size_t path_len);
bool ethereum_path_is_supported(const uint32_t* path, size_t path_len);
bool ethereum_path_is_standard_external(const uint32_t* path, size_t path_len);
bool ethereum_path_is_public_key_export_supported(const uint32_t* path, size_t path_len);

#endif /* ETHEREUM_PATH_H_ */
