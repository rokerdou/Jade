#ifndef TREZOR_USB_HID_H_
#define TREZOR_USB_HID_H_

#include <stdbool.h>

bool trezor_usb_hid_init(void);
void trezor_usb_hid_deinit(void);
bool trezor_usb_hid_enabled(void);

#endif /* TREZOR_USB_HID_H_ */
