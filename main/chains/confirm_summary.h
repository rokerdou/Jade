#ifndef CHAIN_CONFIRM_SUMMARY_H_
#define CHAIN_CONFIRM_SUMMARY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CHAIN_CONFIRM_MAX_FIELDS 12
#define CHAIN_CONFIRM_MAX_BYTES 32
#define CHAIN_CONFIRM_MAX_PATH_LEN 16

#define CHAIN_CONFIRM_FLAG_USER_CONFIRM (1U << 0)
#define CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM (1U << 1)
#define CHAIN_CONFIRM_FLAG_APPROVAL (1U << 2)
#define CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT (1U << 3)

typedef enum {
    CHAIN_CONFIRM_CHAIN_ETHEREUM = 0,
    CHAIN_CONFIRM_CHAIN_TRON,
} chain_confirm_chain_t;

typedef enum {
    CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER = 0,
    CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER,
    CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE,
    CHAIN_CONFIRM_OPERATION_CONTRACT_CALL,
} chain_confirm_operation_t;

typedef enum {
    CHAIN_CONFIRM_FIELD_PATH = 0,
    CHAIN_CONFIRM_FIELD_CHAIN_ID,
    CHAIN_CONFIRM_FIELD_NONCE,
    CHAIN_CONFIRM_FIELD_FROM,
    CHAIN_CONFIRM_FIELD_OWNER,
    CHAIN_CONFIRM_FIELD_TO,
    CHAIN_CONFIRM_FIELD_AMOUNT,
    CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT,
    CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT,
    CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT,
    CHAIN_CONFIRM_FIELD_MAX_FEE,
    CHAIN_CONFIRM_FIELD_FEE_LIMIT,
    CHAIN_CONFIRM_FIELD_CALLDATA_HASH,
} chain_confirm_field_kind_t;

typedef enum {
    CHAIN_CONFIRM_VALUE_U64 = 0,
    CHAIN_CONFIRM_VALUE_BYTES,
    CHAIN_CONFIRM_VALUE_PATH,
} chain_confirm_value_type_t;

typedef struct {
    uint32_t parts[CHAIN_CONFIRM_MAX_PATH_LEN];
    size_t len;
} chain_confirm_path_t;

typedef struct {
    chain_confirm_field_kind_t kind;
    chain_confirm_value_type_t value_type;
    union {
        uint64_t u64;
        struct {
            uint8_t bytes[CHAIN_CONFIRM_MAX_BYTES];
            size_t len;
        } bytes;
        chain_confirm_path_t path;
    } value;
} chain_confirm_field_t;

typedef struct {
    chain_confirm_chain_t chain;
    chain_confirm_operation_t operation;
    uint32_t flags;
    chain_confirm_field_t fields[CHAIN_CONFIRM_MAX_FIELDS];
    size_t num_fields;
} chain_confirm_summary_t;

void chain_confirm_summary_init(
    chain_confirm_summary_t* summary, chain_confirm_chain_t chain, chain_confirm_operation_t operation, uint32_t flags);
bool chain_confirm_summary_add_u64(chain_confirm_summary_t* summary, chain_confirm_field_kind_t kind, uint64_t value);
bool chain_confirm_summary_add_bytes(
    chain_confirm_summary_t* summary, chain_confirm_field_kind_t kind, const uint8_t* bytes, size_t bytes_len);
bool chain_confirm_summary_add_path(
    chain_confirm_summary_t* summary, chain_confirm_field_kind_t kind, const uint32_t* path, size_t path_len);
bool chain_confirm_summary_has_field(const chain_confirm_summary_t* summary, chain_confirm_field_kind_t kind);

#endif /* CHAIN_CONFIRM_SUMMARY_H_ */
