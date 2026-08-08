#ifndef TREZOR_FEATURES_H_
#define TREZOR_FEATURES_H_

#include "messages.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TREZOR_FEATURES_MAX_CAPABILITIES 8
#define TREZOR_FEATURES_SESSION_ID_LEN 32

typedef struct {
    const char* vendor;
    const char* fw_vendor;
    const char* device_id;
    const char* language;
    const char* label;
    const char* model;
    const char* internal_model;
    const uint8_t* session_id;
    size_t session_id_len;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t patch_version;
    bool initialized;
    bool has_unlocked;
    bool unlocked;
    bool pin_protection;
    bool expose_private_fields;
    bool passphrase_protection;
    bool no_backup;
    bool unfinished_backup;
    uint32_t flags;
    trezor_capability_t capabilities[TREZOR_FEATURES_MAX_CAPABILITIES];
    size_t capabilities_len;
} trezor_features_t;

bool trezor_features_encode(const trezor_features_t* features, uint8_t* output, size_t output_len, size_t* written);

#endif /* TREZOR_FEATURES_H_ */
