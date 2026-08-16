#ifndef AMALGAMATED_BUILD
#include "safe_tx.h"

#include "../../crypto/keccak256.h"

#include <stdio.h>
#include <string.h>
#include <wally_crypto.h>

#define ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN 78
#define ETHEREUM_SAFE_AMOUNT_TEXT_MAX_LEN (ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 13)

static const uint8_t ETHEREUM_SAFE_DOMAIN_TYPEHASH[KECCAK256_LEN]
    = { 0x47, 0xe7, 0x95, 0x34, 0xa2, 0x45, 0x95, 0x2e, 0x8b, 0x16, 0x89, 0x3a, 0x33, 0x6b, 0x85, 0xa3,
          0xd9, 0xea, 0x9f, 0xa8, 0xc5, 0x73, 0xf3, 0xd8, 0x03, 0xaf, 0xb9, 0x2a, 0x79, 0x46, 0x92, 0x18 };

static const uint8_t ETHEREUM_SAFE_TX_TYPEHASH[KECCAK256_LEN]
    = { 0xbb, 0x83, 0x10, 0xd4, 0x86, 0x36, 0x8d, 0xb6, 0xbd, 0x6f, 0x84, 0x94, 0x02, 0xfd, 0xd7, 0x3a,
          0xd5, 0x3d, 0x31, 0x6b, 0x5a, 0x4b, 0x26, 0x44, 0xad, 0x6e, 0xfe, 0x0f, 0x94, 0x12, 0x86, 0xd8 };

static bool ethereum_safe_bytes_are_zero(const uint8_t* const bytes, const size_t bytes_len)
{
    if (!bytes) {
        return bytes_len == 0;
    }
    for (size_t i = 0; i < bytes_len; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool ethereum_safe_format_uint256_decimal(
    const uint8_t value[EVM_ABI_WORD_LEN], char* const output, const size_t output_len)
{
    if (!value || !output || output_len == 0) {
        return false;
    }

    uint8_t work[EVM_ABI_WORD_LEN];
    memcpy(work, value, sizeof(work));

    char digits[ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 1];
    size_t digits_len = 0;
    while (true) {
        bool any = false;
        uint16_t rem = 0;
        for (size_t i = 0; i < sizeof(work); ++i) {
            const uint16_t current = (uint16_t)((rem << 8) | work[i]);
            work[i] = (uint8_t)(current / 10U);
            rem = current % 10U;
            any = any || work[i] != 0;
        }
        if (digits_len >= ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN) {
            wally_bzero(work, sizeof(work));
            return false;
        }
        digits[digits_len++] = (char)('0' + rem);
        if (!any) {
            break;
        }
    }

    if (digits_len + 1U > output_len) {
        wally_bzero(work, sizeof(work));
        return false;
    }
    for (size_t i = 0; i < digits_len; ++i) {
        output[i] = digits[digits_len - 1U - i];
    }
    output[digits_len] = '\0';
    wally_bzero(work, sizeof(work));
    return true;
}

static bool ethereum_safe_format_uint256_units(
    const uint8_t value[EVM_ABI_WORD_LEN], const char* const suffix, char* const output, const size_t output_len)
{
    char decimal[ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 1];
    if (!suffix || !ethereum_safe_format_uint256_decimal(value, decimal, sizeof(decimal))) {
        return false;
    }
    const int ret = snprintf(output, output_len, "%s %s", decimal, suffix);
    return ret > 0 && (size_t)ret < output_len;
}

static void write_leftpad_address(uint8_t output[EVM_ABI_WORD_LEN], const uint8_t address[ETHEREUM_ADDRESS_LEN])
{
    wally_bzero(output, EVM_ABI_WORD_LEN);
    memcpy(output + EVM_ABI_ADDRESS_PAD_LEN, address, ETHEREUM_ADDRESS_LEN);
}

static void write_leftpad_u64(uint8_t output[EVM_ABI_WORD_LEN], uint64_t value)
{
    wally_bzero(output, EVM_ABI_WORD_LEN);
    for (size_t i = 0; i < sizeof(value); ++i) {
        output[EVM_ABI_WORD_LEN - 1U - i] = (uint8_t)value;
        value >>= 8;
    }
}

static bool append(uint8_t* const output, const size_t output_len, size_t* const pos, const uint8_t* const data,
    const size_t data_len)
{
    if (!output || !pos || (!data && data_len) || data_len > output_len - *pos) {
        return false;
    }
    if (data_len) {
        memcpy(output + *pos, data, data_len);
        *pos += data_len;
    }
    return true;
}

bool ethereum_safe_tx_validate(const ethereum_safe_tx_t* const tx)
{
    if (!tx || tx->chain_id == 0 || (!tx->data && tx->data_len) || tx->data_len > ETHEREUM_SAFE_TX_MAX_DATA_LEN) {
        return false;
    }
    return tx->operation == ETHEREUM_SAFE_TX_OPERATION_CALL || tx->operation == ETHEREUM_SAFE_TX_OPERATION_DELEGATE_CALL;
}

bool ethereum_safe_tx_domain_separator_hash(
    const uint64_t chain_id, const uint8_t verifying_contract[ETHEREUM_ADDRESS_LEN], uint8_t output[KECCAK256_LEN])
{
    if (chain_id == 0 || !verifying_contract || !output) {
        return false;
    }

    uint8_t payload[KECCAK256_LEN + EVM_ABI_WORD_LEN + EVM_ABI_WORD_LEN];
    size_t pos = 0;
    uint8_t word[EVM_ABI_WORD_LEN];
    const bool ok = append(payload, sizeof(payload), &pos, ETHEREUM_SAFE_DOMAIN_TYPEHASH, sizeof(ETHEREUM_SAFE_DOMAIN_TYPEHASH))
        && (write_leftpad_u64(word, chain_id), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && (write_leftpad_address(word, verifying_contract), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && pos == sizeof(payload) && keccak256(payload, pos, output, KECCAK256_LEN);
    wally_bzero(payload, sizeof(payload));
    wally_bzero(word, sizeof(word));
    return ok;
}

bool ethereum_safe_tx_message_hash(const ethereum_safe_tx_t* const tx, uint8_t output[KECCAK256_LEN])
{
    if (!ethereum_safe_tx_validate(tx) || !output) {
        return false;
    }

    uint8_t calldata_hash[KECCAK256_LEN];
    if (!keccak256(tx->data, tx->data_len, calldata_hash, sizeof(calldata_hash))) {
        return false;
    }

    uint8_t payload[KECCAK256_LEN + (10U * EVM_ABI_WORD_LEN)];
    size_t pos = 0;
    uint8_t word[EVM_ABI_WORD_LEN];

    const bool ok = append(payload, sizeof(payload), &pos, ETHEREUM_SAFE_TX_TYPEHASH, sizeof(ETHEREUM_SAFE_TX_TYPEHASH))
        && (write_leftpad_address(word, tx->to), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && append(payload, sizeof(payload), &pos, tx->value, EVM_ABI_WORD_LEN)
        && append(payload, sizeof(payload), &pos, calldata_hash, sizeof(calldata_hash))
        && (write_leftpad_u64(word, (uint64_t)tx->operation), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && append(payload, sizeof(payload), &pos, tx->safe_tx_gas, EVM_ABI_WORD_LEN)
        && append(payload, sizeof(payload), &pos, tx->base_gas, EVM_ABI_WORD_LEN)
        && append(payload, sizeof(payload), &pos, tx->gas_price, EVM_ABI_WORD_LEN)
        && (write_leftpad_address(word, tx->gas_token), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && (write_leftpad_address(word, tx->refund_receiver), append(payload, sizeof(payload), &pos, word, sizeof(word)))
        && append(payload, sizeof(payload), &pos, tx->nonce, EVM_ABI_WORD_LEN) && pos == sizeof(payload)
        && keccak256(payload, pos, output, KECCAK256_LEN);

    wally_bzero(calldata_hash, sizeof(calldata_hash));
    wally_bzero(payload, sizeof(payload));
    wally_bzero(word, sizeof(word));
    return ok;
}

bool ethereum_safe_tx_signing_hash(const ethereum_safe_tx_t* const tx, uint8_t output[ETHEREUM_TX_SIGNING_HASH_LEN])
{
    if (!ethereum_safe_tx_validate(tx) || !output) {
        return false;
    }

    uint8_t domain_hash[KECCAK256_LEN];
    uint8_t message_hash[KECCAK256_LEN];
    uint8_t payload[2U + (2U * KECCAK256_LEN)];
    const uint8_t prefix[2] = { 0x19, 0x01 };
    size_t pos = 0;

    const bool ok = ethereum_safe_tx_domain_separator_hash(tx->chain_id, tx->verifying_contract, domain_hash)
        && ethereum_safe_tx_message_hash(tx, message_hash) && append(payload, sizeof(payload), &pos, prefix, sizeof(prefix))
        && append(payload, sizeof(payload), &pos, domain_hash, sizeof(domain_hash))
        && append(payload, sizeof(payload), &pos, message_hash, sizeof(message_hash)) && pos == sizeof(payload)
        && keccak256(payload, pos, output, ETHEREUM_TX_SIGNING_HASH_LEN);

    wally_bzero(domain_hash, sizeof(domain_hash));
    wally_bzero(message_hash, sizeof(message_hash));
    wally_bzero(payload, sizeof(payload));
    return ok;
}

bool ethereum_safe_tx_preflight(const ethereum_safe_tx_t* const tx, ethereum_safe_tx_summary_t* const summary)
{
    if (!ethereum_safe_tx_validate(tx) || !summary || tx->operation != ETHEREUM_SAFE_TX_OPERATION_CALL
        || (tx->data_len && !tx->data) || !ethereum_safe_bytes_are_zero(tx->gas_token, sizeof(tx->gas_token))
        || !ethereum_safe_bytes_are_zero(tx->refund_receiver, sizeof(tx->refund_receiver))) {
        return false;
    }

    wally_bzero(summary, sizeof(*summary));
    if (!keccak256(tx->data, tx->data_len, summary->calldata_hash, sizeof(summary->calldata_hash))) {
        return false;
    }
    memcpy(summary->safe_address, tx->verifying_contract, sizeof(summary->safe_address));
    memcpy(summary->to, tx->to, sizeof(summary->to));
    if (tx->data_len == 0) {
        summary->type = ETHEREUM_SAFE_TX_SUMMARY_NATIVE_TRANSFER;
        return true;
    }

    evm_abi_address_uint256_call_t call;
    if (evm_abi_parse_address_uint256_call(tx->data, tx->data_len, &call)) {
        if (!ethereum_safe_bytes_are_zero(tx->value, sizeof(tx->value))) {
            wally_bzero(&call, sizeof(call));
            return false;
        }
        summary->type = call.type == EVM_ABI_CALL_ERC20_TRANSFER ? ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER
                                                                 : ETHEREUM_SAFE_TX_SUMMARY_ERC20_APPROVE;
        memcpy(summary->token_contract, tx->to, sizeof(summary->token_contract));
        memcpy(summary->token_recipient, call.address, sizeof(summary->token_recipient));
        memcpy(summary->token_amount, call.amount, sizeof(summary->token_amount));
        wally_bzero(&call, sizeof(call));
        return true;
    }

    summary->type = ETHEREUM_SAFE_TX_SUMMARY_CONTRACT_CALL;
    return true;
}

static chain_confirm_operation_t safe_confirm_operation_from_result(const ethereum_safe_tx_summary_t* const result)
{
    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_TRANSFER;
    }
    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_APPROVE) {
        return CHAIN_CONFIRM_OPERATION_TOKEN_APPROVE;
    }
    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_CONTRACT_CALL) {
        return CHAIN_CONFIRM_OPERATION_CONTRACT_CALL;
    }
    return CHAIN_CONFIRM_OPERATION_NATIVE_TRANSFER;
}

bool ethereum_safe_tx_confirm_summary_from_preflight(const uint32_t* const path, const size_t path_len,
    const ethereum_safe_tx_t* const tx, const ethereum_safe_tx_summary_t* const result,
    const uint8_t signing_hash[ETHEREUM_TX_SIGNING_HASH_LEN], chain_confirm_summary_t* const summary)
{
    if (!path || path_len == 0 || !tx || !result || result->type == ETHEREUM_SAFE_TX_SUMMARY_UNSUPPORTED
        || !signing_hash || !summary || !ethereum_safe_tx_validate(tx)) {
        return false;
    }

    uint32_t flags = CHAIN_CONFIRM_FLAG_USER_CONFIRM;
    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_APPROVE) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_APPROVAL;
    } else if (result->type == ETHEREUM_SAFE_TX_SUMMARY_CONTRACT_CALL) {
        flags |= CHAIN_CONFIRM_FLAG_EXTRA_CONFIRM | CHAIN_CONFIRM_FLAG_UNKNOWN_CONTRACT;
    }

    char nonce[ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 1];
    char safe_tx_gas[ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 1];
    char base_gas[ETHEREUM_SAFE_UINT256_DECIMAL_MAX_LEN + 1];
    char gas_price[ETHEREUM_SAFE_AMOUNT_TEXT_MAX_LEN];
    if (!ethereum_safe_format_uint256_decimal(tx->nonce, nonce, sizeof(nonce))
        || !ethereum_safe_format_uint256_decimal(tx->safe_tx_gas, safe_tx_gas, sizeof(safe_tx_gas))
        || !ethereum_safe_format_uint256_decimal(tx->base_gas, base_gas, sizeof(base_gas))
        || !ethereum_safe_format_uint256_units(tx->gas_price, "wei", gas_price, sizeof(gas_price))) {
        return false;
    }

    chain_confirm_summary_init(
        summary, CHAIN_CONFIRM_CHAIN_ETHEREUM, safe_confirm_operation_from_result(result), flags);
    if (!chain_confirm_summary_add_path(summary, CHAIN_CONFIRM_FIELD_PATH, path, path_len)
        || !chain_confirm_summary_add_u64(summary, CHAIN_CONFIRM_FIELD_CHAIN_ID, tx->chain_id)
        || !chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_NONCE, nonce)
        || !chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_SAFE, result->safe_address,
            sizeof(result->safe_address))
        || !chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_SAFE_TX_GAS, safe_tx_gas)
        || !chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_BASE_GAS, base_gas)
        || !chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_GAS_PRICE, gas_price)) {
        return false;
    }

    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_NATIVE_TRANSFER) {
        char amount[ETHEREUM_SAFE_AMOUNT_TEXT_MAX_LEN];
        return ethereum_safe_format_uint256_units(tx->value, "wei", amount, sizeof(amount))
            && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TO, result->to, sizeof(result->to))
            && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_AMOUNT, amount)
            && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_SAFE_TX_HASH, signing_hash,
                ETHEREUM_TX_SIGNING_HASH_LEN);
    }

    if (result->type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_TRANSFER
        || result->type == ETHEREUM_SAFE_TX_SUMMARY_ERC20_APPROVE) {
        char token_amount[ETHEREUM_SAFE_AMOUNT_TEXT_MAX_LEN];
        return ethereum_safe_format_uint256_units(result->token_amount, "units", token_amount, sizeof(token_amount))
            && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TOKEN_CONTRACT, result->token_contract,
                sizeof(result->token_contract))
            && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TOKEN_RECIPIENT, result->token_recipient,
                sizeof(result->token_recipient))
            && chain_confirm_summary_add_text(summary, CHAIN_CONFIRM_FIELD_TOKEN_AMOUNT, token_amount)
            && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_SAFE_TX_HASH, signing_hash,
                ETHEREUM_TX_SIGNING_HASH_LEN);
    }

    return chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_TO, result->to, sizeof(result->to))
        && chain_confirm_summary_add_bytes(summary, CHAIN_CONFIRM_FIELD_CALLDATA_HASH, result->calldata_hash,
            sizeof(result->calldata_hash))
        && chain_confirm_summary_add_bytes(
            summary, CHAIN_CONFIRM_FIELD_SAFE_TX_HASH, signing_hash, ETHEREUM_TX_SIGNING_HASH_LEN);
}
#endif /* AMALGAMATED_BUILD */
