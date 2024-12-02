#include <string.h>
#include "rc522_types_internal.h"
#include "rc522_internal.h"
#include "rc522_helpers_internal.h"
#include "rc522_pcd_internal.h"
#include "rc522_picc_internal.h"
#include "picc/rc522_ntag.h"

RC522_LOG_DEFINE_BASE();

enum
{
    /**
     * Reads one 16 byte block from the authenticated sector of the PICC
     */
    RC522_NTAG_READ_CMD = 0x30,

    /**
     * Writes one 16 byte block to the authenticated sector of the PICC
     */
    RC522_NTAG_WRITE_CMD = 0xA0,
};



esp_err_t rc522_ntag_read(const rc522_handle_t rc522, const rc522_picc_t *picc, uint8_t page_address,
    uint8_t out_buffer[NTAG_PAGE_SIZE])
{
    RC522_CHECK(rc522 == NULL);
    RC522_CHECK(picc == NULL);
    RC522_CHECK(out_buffer == NULL);

    RC522_LOGD("NTAG READ (page_address=%02" RC522_X ")", page_address);

    uint8_t cmd_buffer[4] = { 0 };

    // Build command buffer
    cmd_buffer[0] = RC522_NTAG_READ_CMD;
    cmd_buffer[1] = page_address;

    // Calculate CRC_A
    rc522_pcd_crc_t crc = { 0 };
    RC522_RETURN_ON_ERROR(rc522_pcd_calculate_crc(rc522, &(rc522_bytes_t) { .ptr = cmd_buffer, .length = 2 }, &crc));

    cmd_buffer[2] = crc.lsb;
    cmd_buffer[3] = crc.msb;

    uint8_t block_buffer[NTAG_PAGE_READ_SIZE + 2] = { 0 }; // +2 for CRC_A

    rc522_picc_transaction_t transaction = {
        .bytes = { .ptr = cmd_buffer, .length = sizeof(cmd_buffer) },
        .check_crc = true,
    };

    rc522_picc_transaction_result_t result = {
        .bytes = { .ptr = block_buffer, .length = sizeof(block_buffer) },
    };

    RC522_RETURN_ON_ERROR(rc522_picc_transceive(rc522, &transaction, &result));
    RC522_CHECK_AND_RETURN((result.bytes.length - 2) != NTAG_PAGE_READ_SIZE, ESP_FAIL);

    memcpy(out_buffer, block_buffer, NTAG_PAGE_SIZE); // -2 cuz of CRC_A

    return ESP_OK;
}
