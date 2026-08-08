#ifndef TRON_PATH_H_
#define TRON_PATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRON_SLIP44 195UL

typedef enum {
    TRON_PATH_UNSUPPORTED = 0,
    TRON_PATH_BIP44_EXTERNAL,
    TRON_PATH_BIP44_CHANGE,
} tron_path_kind_t;

tron_path_kind_t tron_path_classify(const uint32_t* path, size_t path_len);
bool tron_path_is_supported(const uint32_t* path, size_t path_len);
bool tron_path_is_standard_external(const uint32_t* path, size_t path_len);

#endif /* TRON_PATH_H_ */
