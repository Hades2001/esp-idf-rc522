#pragma once

#include "rc522_types.h"
#include "rc522_picc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NTAG_PAGE_SIZE  (4)
#define NTAG_PAGE_READ_SIZE (16)

esp_err_t rc522_ntag_read(const rc522_handle_t rc522, const rc522_picc_t *picc, uint8_t block_address,
    uint8_t out_buffer[NTAG_PAGE_SIZE]);

#ifdef __cplusplus
}
#endif
