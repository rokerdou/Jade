#ifndef AMALGAMATED_BUILD
#include "features.h"

#include "protobuf.h"

bool trezor_features_encode(
    const trezor_features_t* const features, uint8_t* const output, const size_t output_len, size_t* const written)
{
    if (!features || !output || !written || !features->vendor || !features->model || !features->internal_model
        || features->capabilities_len > TREZOR_FEATURES_MAX_CAPABILITIES) {
        return false;
    }

    trezor_protobuf_writer_t writer;
    trezor_protobuf_writer_init(&writer, output, output_len);

    bool ok = trezor_protobuf_write_string_field(&writer, 1, features->vendor)
        && trezor_protobuf_write_varint_field(&writer, 2, features->major_version)
        && trezor_protobuf_write_varint_field(&writer, 3, features->minor_version)
        && trezor_protobuf_write_varint_field(&writer, 4, features->patch_version);

    if (ok && features->device_id) {
        ok = trezor_protobuf_write_string_field(&writer, 6, features->device_id);
    }

    ok = ok && trezor_protobuf_write_bool_field(&writer, 7, features->pin_protection);

    if (ok && features->expose_private_fields) {
        ok = trezor_protobuf_write_bool_field(&writer, 8, features->passphrase_protection);
    }

    if (ok && features->language) {
        ok = trezor_protobuf_write_string_field(&writer, 9, features->language);
    }

    if (ok && features->label) {
        ok = trezor_protobuf_write_string_field(&writer, 10, features->label);
    }

    ok = ok && trezor_protobuf_write_bool_field(&writer, 12, features->initialized)
        && trezor_protobuf_write_bool_field(&writer, 15, false);

    if (ok && features->has_unlocked) {
        ok = trezor_protobuf_write_bool_field(&writer, 16, features->unlocked);
    }

    ok = ok && trezor_protobuf_write_bool_field(&writer, 18, true);

    if (ok && features->expose_private_fields) {
        ok = trezor_protobuf_write_varint_field(&writer, 19, 0)
            && trezor_protobuf_write_varint_field(&writer, 20, features->flags);
    }

    ok = ok && trezor_protobuf_write_string_field(&writer, 21, features->model);

    for (size_t i = 0; ok && i < features->capabilities_len; ++i) {
        ok = trezor_protobuf_write_varint_field(&writer, 30, features->capabilities[i]);
    }

    if (ok && features->fw_vendor) {
        ok = trezor_protobuf_write_string_field(&writer, 25, features->fw_vendor);
    }

    if (ok && features->session_id && features->session_id_len == TREZOR_FEATURES_SESSION_ID_LEN) {
        ok = trezor_protobuf_write_bytes_field(&writer, 35, features->session_id, features->session_id_len);
    }

    if (ok && features->expose_private_fields) {
        ok = trezor_protobuf_write_bool_field(&writer, 27, features->unfinished_backup)
            && trezor_protobuf_write_bool_field(&writer, 28, features->no_backup)
            && trezor_protobuf_write_varint_field(&writer, 31, 0)
            && trezor_protobuf_write_varint_field(&writer, 37, 0);
    }

    ok = ok && trezor_protobuf_write_bool_field(&writer, 41, false)
        && trezor_protobuf_write_string_field(&writer, 44, features->internal_model)
        && trezor_protobuf_write_bool_field(&writer, 50, true)
        && trezor_protobuf_write_bool_field(&writer, 59, true);
    if (!ok) {
        return false;
    }

    *written = writer.len;
    return true;
}
#endif /* AMALGAMATED_BUILD */
