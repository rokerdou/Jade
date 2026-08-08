#ifndef LEDGER_APDU_H_
#define LEDGER_APDU_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LEDGER_SW_OK 0x9000
#define LEDGER_SW_WRONG_LENGTH 0x6700
#define LEDGER_SW_CONDITIONS_NOT_SATISFIED 0x6985
#define LEDGER_SW_DATA_INVALID 0x6A80
#define LEDGER_SW_INS_NOT_SUPPORTED 0x6D00
#define LEDGER_SW_CLA_NOT_SUPPORTED 0x6E00
#define LEDGER_SW_UNKNOWN 0x6F00

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    const uint8_t* data;
    size_t data_len;
} ledger_apdu_t;

bool ledger_apdu_decode(const uint8_t* input, size_t input_len, ledger_apdu_t* apdu, uint16_t* status_word);
bool ledger_apdu_dispatch(
    const ledger_apdu_t* apdu, uint8_t* response, size_t response_len, size_t* written, uint16_t* status_word);

#endif /* LEDGER_APDU_H_ */
