#include <string.h>
#include "rc522_types_internal.h"
#include "rc522_internal.h"
#include "rc522_helpers_internal.h"
#include "rc522_pcd_internal.h"
#include "rc522_picc_internal.h"
#include "picc/rc522_ntag.h"



#define TAG "NTAG"

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

esp_err_t rc522_ntag_readn(const rc522_handle_t rc522, const rc522_picc_t *picc, uint16_t address,uint8_t* out_buffer,int len)
{
    if((out_buffer == NULL) ||(len <= 0)){
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t read_buff[NTAG_PAGE_SIZE];
    uint16_t offset,write_offset = 0;
    uint8_t page,cpy_num;
    int buff_len = len;

    page = address / 4;
    offset = address % 4;
    len += offset;

    while(len > 0){
        rc522_ntag_read(rc522,picc,page,read_buff);
        len -= 4;
        page++;
        cpy_num = (len < 0 ) ? (4 - offset + len):(4-offset);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG,&read_buff[offset],4,ESP_LOG_INFO);
        memcpy((out_buffer + write_offset),&read_buff[offset],4-offset);
        offset = (offset != 0 ) ? 0 : offset;
        write_offset += cpy_num;
        ESP_LOGI(TAG,"len:%d,page:%d,cpy_num:%d,offset:%d",len,page,cpy_num,offset);
    }
    //ESP_LOG_BUFFER_HEX_LEVEL(TAG,out_buffer,buff_len,ESP_LOG_INFO);

    return ESP_OK; 
}


typedef struct ntag_tvl_info{
    uint8_t type;
    int blocklen;
    int start_addr;
}ntag_tvl_info_t;

esp_err_t ntag_get_tlv_info(const rc522_handle_t rc522, const rc522_picc_t *picc, ntag_tvl_info_t* tvl_info)
{
    if( tvl_info == NULL ){
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t tvl_buff[NTAG_PAGE_SIZE];
    ESP_RETURN_ON_ERROR(rc522_ntag_read(rc522,picc,4,tvl_buff),TAG,"NTAG read fault");
   
    tvl_info->type = tvl_buff[0];
    if(tvl_buff[1] != 0xff){
        tvl_info->blocklen = tvl_buff[1];
        tvl_info->start_addr = 4*4+2;
    } else
    {
        tvl_info->blocklen = ((int)tvl_buff[2] << 8) + tvl_buff[3];
        tvl_info->start_addr = 5*4;
    }
    return ESP_OK;
}

typedef struct ntag_ndef_info{
    uint8_t type;
    int blocklen;
    int start_addr;
}ntag_ndef_info;

esp_err_t ntag_NDEF_index(const rc522_handle_t rc522, const rc522_picc_t *picc)
{

}