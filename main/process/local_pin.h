#ifndef LOCAL_PIN_H_
#define LOCAL_PIN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool local_pin_get_aeskey(const uint8_t* pin, size_t pin_len, uint8_t* aeskey, size_t aeskey_len);
bool local_pin_set_aeskey(const uint8_t* pin, size_t pin_len, uint8_t* aeskey, size_t aeskey_len);

#endif /* LOCAL_PIN_H_ */
