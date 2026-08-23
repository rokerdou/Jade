#ifndef UI_CHAIN_CONFIRM_FORMAT_H_
#define UI_CHAIN_CONFIRM_FORMAT_H_

#include <stdbool.h>
#include <stddef.h>

bool chain_confirm_ui_copy_text_line(
    char* output, size_t output_len, const char* text, size_t text_len, size_t offset, size_t* consumed);
bool chain_confirm_ui_copy_hex_line(
    char* output, size_t output_len, const char* hex, size_t hex_len, size_t offset, size_t* consumed);

#endif /* UI_CHAIN_CONFIRM_FORMAT_H_ */
