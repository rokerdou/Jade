#ifndef AMALGAMATED_BUILD
#include "multisig.h"

#include "messages.h"
#include "../protobuf.h"
#include "../../../chains/bitcoin/path.h"
#include "../../../jade_wally_verify.h"

#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>

#define TREZOR_BITCOIN_MULTISIG_ORDER_PRESERVED 0U
#define TREZOR_BITCOIN_MULTISIG_ORDER_LEXICOGRAPHIC 1U

static bool read_varint_u32(const uint8_t* const value, const size_t value_len, uint32_t* const output)
{
    uint64_t raw = 0;
    if (!output || !trezor_protobuf_read_varint_value(value, value_len, &raw) || raw > UINT32_MAX) {
        return false;
    }
    *output = (uint32_t)raw;
    return true;
}

static void write_be32(uint8_t* const output, const uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static bool path_has_hardened(const uint32_t* const path, const size_t path_len)
{
    if (!path) {
        return true;
    }
    for (size_t i = 0; i < path_len; ++i) {
        if ((path[i] & 0x80000000U) != 0) {
            return true;
        }
    }
    return false;
}

static bool hd_node_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_hd_node_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (payload_len && reader.len == 0) {
        return false;
    }

    bool has_depth = false;
    bool has_fingerprint = false;
    bool has_child_num = false;
    bool has_chain_code = false;
    bool has_public_key = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == 1) {
            uint32_t depth = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !read_varint_u32(value, value_len, &depth)
                || depth > UINT8_MAX) {
                return false;
            }
            output->depth = (uint8_t)depth;
            has_depth = true;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !read_varint_u32(value, value_len, &output->fingerprint)) {
                return false;
            }
            has_fingerprint = true;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !read_varint_u32(value, value_len, &output->child_num)) {
                return false;
            }
            has_child_num = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len != sizeof(output->chain_code)) {
                return false;
            }
            memcpy(output->chain_code, value, value_len);
            has_chain_code = true;
        } else if (field_number == 5) {
            return false;
        } else if (field_number == 6) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || value_len != sizeof(output->public_key)
                || (value[0] != 0x02 && value[0] != 0x03)
                || wally_ec_public_key_verify(value, value_len) != WALLY_OK) {
                return false;
            }
            memcpy(output->public_key, value, value_len);
            has_public_key = true;
        } else {
            return false;
        }
    }

    return has_depth && has_fingerprint && has_child_num && has_chain_code && has_public_key;
}

static bool hd_node_path_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_hd_node_path_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (payload_len && reader.len == 0) {
        return false;
    }

    bool has_node = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || has_node
                || !hd_node_decode(value, value_len, &output->node)) {
                return false;
            }
            has_node = true;
        } else if (field_number == 2) {
            uint32_t path_part = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !read_varint_u32(value, value_len, &path_part)) {
                return false;
            }
            output->address_n[output->address_n_len++] = path_part;
        } else {
            return false;
        }
    }

    return has_node && !path_has_hardened(output->address_n, output->address_n_len);
}

bool trezor_bitcoin_multisig_decode(
    const uint8_t* const payload, const size_t payload_len, trezor_bitcoin_multisig_t* const output)
{
    if (!payload || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    trezor_protobuf_reader_t reader;
    trezor_protobuf_reader_init(&reader, payload, payload_len);
    if (payload_len && reader.len == 0) {
        return false;
    }

    bool has_threshold = false;
    output->sorted = false;
    while (reader.pos < reader.len) {
        uint32_t field_number = 0;
        uint8_t wire_type = 0;
        const uint8_t* value = NULL;
        size_t value_len = 0;
        if (!trezor_protobuf_reader_next(&reader, &field_number, &wire_type, &value, &value_len)) {
            return false;
        }
        if (field_number == 1) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || output->pubkeys_len >= TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS
                || !hd_node_path_decode(value, value_len, &output->pubkeys[output->pubkeys_len])) {
                return false;
            }
            ++output->pubkeys_len;
        } else if (field_number == 2) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN
                || output->signatures_len >= TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS
                || value_len > TREZOR_BITCOIN_MULTISIG_SIGNATURE_MAX_LEN) {
                return false;
            }
            memcpy(output->signatures[output->signatures_len], value, value_len);
            output->signature_lens[output->signatures_len++] = value_len;
        } else if (field_number == 3) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !read_varint_u32(value, value_len, &output->threshold)) {
                return false;
            }
            has_threshold = true;
        } else if (field_number == 4) {
            if (wire_type != TREZOR_PROTOBUF_WIRE_LEN || output->nodes_len >= TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS
                || !hd_node_decode(value, value_len, &output->nodes[output->nodes_len])) {
                return false;
            }
            ++output->nodes_len;
        } else if (field_number == 5) {
            uint32_t path_part = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || output->address_n_len >= WALLET_CORE_MAX_PATH_LEN
                || !read_varint_u32(value, value_len, &path_part)) {
                return false;
            }
            output->address_n[output->address_n_len++] = path_part;
        } else if (field_number == 6) {
            uint32_t order = 0;
            if (wire_type != TREZOR_PROTOBUF_WIRE_VARINT || !read_varint_u32(value, value_len, &order)
                || (order != TREZOR_BITCOIN_MULTISIG_ORDER_PRESERVED
                    && order != TREZOR_BITCOIN_MULTISIG_ORDER_LEXICOGRAPHIC)) {
                return false;
            }
            output->sorted = order == TREZOR_BITCOIN_MULTISIG_ORDER_LEXICOGRAPHIC;
        } else {
            return false;
        }
    }

    const bool old_style = output->pubkeys_len > 0 && output->nodes_len == 0 && output->address_n_len == 0;
    const bool new_style = output->pubkeys_len == 0 && output->nodes_len > 0;
    const size_t num_pubkeys = old_style ? output->pubkeys_len : output->nodes_len;
    return has_threshold && (old_style || new_style) && output->threshold > 0 && output->threshold <= num_pubkeys
        && output->signatures_len <= num_pubkeys && !path_has_hardened(output->address_n, output->address_n_len);
}

static bool hd_node_to_ext_key(const trezor_bitcoin_hd_node_t* const node, struct ext_key* const output)
{
    if (!node || !output) {
        return false;
    }

    uint8_t serialized[BIP32_SERIALIZED_LEN];
    size_t offset = 0;
    write_be32(serialized + offset, BIP32_VER_MAIN_PUBLIC);
    offset += sizeof(uint32_t);
    serialized[offset++] = node->depth;
    write_be32(serialized + offset, node->fingerprint);
    offset += sizeof(uint32_t);
    write_be32(serialized + offset, node->child_num);
    offset += sizeof(uint32_t);
    memcpy(serialized + offset, node->chain_code, sizeof(node->chain_code));
    offset += sizeof(node->chain_code);
    memcpy(serialized + offset, node->public_key, sizeof(node->public_key));
    offset += sizeof(node->public_key);

    const bool ok = offset == sizeof(serialized) && bip32_key_unserialize(serialized, sizeof(serialized), output) == WALLY_OK
        && (output->pub_key[0] == 0x02 || output->pub_key[0] == 0x03);
    JADE_WALLY_VERIFY(wally_bzero(serialized, sizeof(serialized)));
    return ok;
}

static bool derive_node_public_key(const trezor_bitcoin_hd_node_t* const node, const uint32_t* const path,
    const size_t path_len, uint8_t* const output, const size_t output_len)
{
    if (!node || !output || output_len != EC_PUBLIC_KEY_LEN || path_has_hardened(path, path_len)) {
        return false;
    }

    struct ext_key root;
    struct ext_key derived;
    wally_bzero(&root, sizeof(root));
    wally_bzero(&derived, sizeof(derived));
    const bool ok = hd_node_to_ext_key(node, &root)
        && bip32_key_from_parent_path(&root, path, path_len, BIP32_FLAG_KEY_PUBLIC, &derived) == WALLY_OK
        && (derived.pub_key[0] == 0x02 || derived.pub_key[0] == 0x03);
    if (ok) {
        memcpy(output, derived.pub_key, output_len);
    }
    wally_bzero(&root, sizeof(root));
    wally_bzero(&derived, sizeof(derived));
    return ok;
}

static bool script_variant_from_script_type(const uint32_t script_type, script_variant_t* const output)
{
    if (!output) {
        return false;
    }
    if (script_type == BITCOIN_MULTISIG_SPENDMULTISIG) {
        *output = MULTI_P2SH;
        return true;
    }
    if (script_type == BITCOIN_P2WPKH_SPENDWITNESS) {
        *output = MULTI_P2WSH;
        return true;
    }
    if (script_type == BITCOIN_P2SH_P2WPKH_SPENDP2SHWITNESS) {
        *output = MULTI_P2WSH_P2SH;
        return true;
    }
    return false;
}

static bool build_multisig_script_pubkey(trezor_bitcoin_multisig_policy_t* const policy)
{
    if (!policy || !is_multisig(policy->variant) || policy->threshold == 0 || policy->num_pubkeys == 0
        || policy->threshold > policy->num_pubkeys || policy->num_pubkeys > TREZOR_BITCOIN_MULTISIG_MAX_SIGNERS) {
        return false;
    }

    const uint32_t flags = policy->sorted ? WALLY_SCRIPT_MULTISIG_SORTED : 0;
    if (wally_scriptpubkey_multisig_from_bytes(policy->pubkeys, policy->num_pubkeys * EC_PUBLIC_KEY_LEN,
            policy->threshold, flags, policy->redeem_script, sizeof(policy->redeem_script),
            &policy->redeem_script_len)
        != WALLY_OK) {
        return false;
    }

    if (policy->variant == MULTI_P2SH) {
        return wally_scriptpubkey_p2sh_from_bytes(policy->redeem_script, policy->redeem_script_len,
                   WALLY_SCRIPT_HASH160, policy->script_pubkey, sizeof(policy->script_pubkey),
                   &policy->script_pubkey_len)
            == WALLY_OK;
    }
    if (policy->variant == MULTI_P2WSH) {
        return wally_witness_program_from_bytes(policy->redeem_script, policy->redeem_script_len,
                   WALLY_SCRIPT_SHA256, policy->script_pubkey, sizeof(policy->script_pubkey),
                   &policy->script_pubkey_len)
            == WALLY_OK;
    }
    if (policy->variant == MULTI_P2WSH_P2SH) {
        uint8_t witness_scriptpubkey[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
        size_t witness_scriptpubkey_len = 0;
        wally_bzero(witness_scriptpubkey, sizeof(witness_scriptpubkey));
        const bool ok = wally_witness_program_from_bytes(policy->redeem_script, policy->redeem_script_len,
                            WALLY_SCRIPT_SHA256, witness_scriptpubkey, sizeof(witness_scriptpubkey),
                            &witness_scriptpubkey_len)
                == WALLY_OK
            && witness_scriptpubkey_len == sizeof(witness_scriptpubkey)
            && wally_scriptpubkey_p2sh_from_bytes(witness_scriptpubkey, witness_scriptpubkey_len,
                   WALLY_SCRIPT_HASH160, policy->script_pubkey, sizeof(policy->script_pubkey),
                   &policy->script_pubkey_len)
                == WALLY_OK;
        wally_bzero(witness_scriptpubkey, sizeof(witness_scriptpubkey));
        return ok;
    }
    return false;
}

bool trezor_bitcoin_multisig_normalize(const trezor_bitcoin_multisig_t* const multisig, const uint32_t script_type,
    trezor_bitcoin_multisig_policy_t* const output)
{
    if (!multisig || !output) {
        return false;
    }

    wally_bzero(output, sizeof(*output));
    if (!script_variant_from_script_type(script_type, &output->variant)) {
        return false;
    }
    output->threshold = (uint8_t)multisig->threshold;
    output->sorted = multisig->sorted;

    if (multisig->pubkeys_len > 0) {
        output->num_pubkeys = multisig->pubkeys_len;
        for (size_t i = 0; i < multisig->pubkeys_len; ++i) {
            if (!derive_node_public_key(&multisig->pubkeys[i].node, multisig->pubkeys[i].address_n,
                    multisig->pubkeys[i].address_n_len, output->pubkeys + (i * EC_PUBLIC_KEY_LEN), EC_PUBLIC_KEY_LEN)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
        }
    } else if (multisig->nodes_len > 0) {
        output->num_pubkeys = multisig->nodes_len;
        output->address_n_len = multisig->address_n_len;
        memcpy(output->address_n, multisig->address_n, multisig->address_n_len * sizeof(multisig->address_n[0]));
        for (size_t i = 0; i < multisig->nodes_len; ++i) {
            if (!derive_node_public_key(&multisig->nodes[i], multisig->address_n, multisig->address_n_len,
                    output->pubkeys + (i * EC_PUBLIC_KEY_LEN), EC_PUBLIC_KEY_LEN)) {
                wally_bzero(output, sizeof(*output));
                return false;
            }
        }
    } else {
        return false;
    }

    if (!build_multisig_script_pubkey(output)) {
        wally_bzero(output, sizeof(*output));
        return false;
    }
    return true;
}

bool trezor_bitcoin_multisig_script_pubkey_matches(const trezor_bitcoin_multisig_policy_t* const policy,
    const uint8_t* const script_pubkey, const size_t script_pubkey_len)
{
    return policy && script_pubkey && policy->script_pubkey_len == script_pubkey_len
        && memcmp(policy->script_pubkey, script_pubkey, script_pubkey_len) == 0;
}
#endif /* AMALGAMATED_BUILD */
