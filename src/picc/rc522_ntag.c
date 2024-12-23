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
        ESP_LOGD(TAG,"len:%d,page:%d,cpy_num:%d,offset:%d",len,page,cpy_num,offset);
    }

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
    ESP_LOGI(TAG,"TVL Info length:%d,start addr:%d",tvl_info->blocklen,tvl_info->start_addr);
    return ESP_OK;
}

// Define the union for an NDEF record header
typedef union NDEFHeader {
    uint8_t byte;
    struct {
        uint8_t TNF : 3; // Type Name Format
        uint8_t IL : 1;  // ID Length Present
        uint8_t SR : 1;  // Short Record
        uint8_t CF : 1;  // Chunk Flag
        uint8_t ME : 1;  // Message End
        uint8_t MB : 1;  // Message Begin
    } bits;
} NDEFHeader;

// Define the structure for a linked list node representing an NDEF record
typedef struct ndef_record {
    NDEFHeader header;       // NDEF record header
    uint32_t payload_length; // Length of the payload
    uint8_t type_length;     // Length of the type field
    uint8_t id_length;       // Length of the ID field (if present)
    uint8_t lang_code_length; // Length of the language code (if present)
    uint8_t *lang_code;      // Pointer to the language code field
    uint8_t *type;           // Pointer to the type field
    uint8_t *id;             // Pointer to the ID field (if present)
    uint8_t *payload;        // Pointer to the payload data
    struct ndef_record *next; // Pointer to the next NDEF record
} ndef_record;

// Function to parse the NDEF header from a byte
NDEFHeader parse_header(uint8_t byte) {
    NDEFHeader header;
    header.byte = byte;
    return header;
}

// Function to create a new NDEF record node
ndef_record *create_ndef_record(NDEFHeader header, uint32_t payload_length, uint8_t type_length, uint8_t id_length, uint8_t lang_code_length, uint8_t *lang_code, uint8_t *type, uint8_t *id, uint8_t *payload) {
    ndef_record *record = (ndef_record *)malloc(sizeof(ndef_record));
    if (!record) {
        ESP_LOGE(TAG, "Failed to allocate memory for NDEF record");
        exit(EXIT_FAILURE);
    }
    record->header = header;
    record->payload_length = payload_length;
    record->type_length = type_length;
    record->id_length = id_length;
    record->lang_code_length = lang_code_length;
    record->lang_code = lang_code;
    record->type = type;
    record->id = id;
    record->payload = payload;
    record->next = NULL;
    return record;
}

// Function to parse NDEF records from raw data
ndef_record *parse_ndef_records(uint8_t *data, size_t length) {
    size_t offset = 0;
    ndef_record *head = NULL;
    ndef_record *current = NULL;

    while (offset < length) {
        // Parse the NDEF header
        NDEFHeader header = parse_header(data[offset++]);

        // Parse the type length
        uint8_t type_length = data[offset++];

        // Parse the payload length
        uint32_t payload_length = 0;
        if (header.bits.SR) {
            payload_length = data[offset++];
        } else {
            payload_length = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
        }

        // Parse the type field
        uint8_t *type = &data[offset];
        offset += type_length;

        // Parse the ID field (if present)
        uint8_t id_length = 0;
        uint8_t *id = NULL;
        if (header.bits.IL) {
            id_length = data[offset++];
            id = &data[offset];
            offset += id_length;
        }

        // Parse the language code (if payload is text)
        uint8_t lang_code_length = 0;
        uint8_t *lang_code = NULL;
        if (header.bits.TNF == 0x01 && type_length == 1 && type[0] == 'T') { // Text record type
            lang_code_length = data[offset++];
            lang_code = &data[offset];
            offset += lang_code_length;
            payload_length = payload_length - lang_code_length - 1;
        }

        // Parse the payload
        uint8_t *payload = &data[offset];
        offset += payload_length; // Corrected offset calculation

        // Create a new NDEF record
        ndef_record *new_record = create_ndef_record(header, payload_length, type_length, id_length, lang_code_length, lang_code, type, id, payload);

        // Add the record to the linked list
        if (head == NULL) {
            head = new_record;
        } else {
            current->next = new_record;
        }
        current = new_record;

        // Check if this is the last record
        if (header.bits.ME) {
            break;
        }
    }

    return head;
}
// Function to print the parsed NDEF records
void print_ndef_records(ndef_record *head) {
    ndef_record *current = head;
    int record_number = 1;

    while (current) {
        ESP_LOGI(TAG,"Record %d:", record_number++);
        ESP_LOGI(TAG,"--MB: %d,ME: %d,CF: %d,SR: %d,IL: %d,TNF: %d", 
                                            current->header.bits.MB,
                                            current->header.bits.ME,
                                            current->header.bits.CF,
                                            current->header.bits.SR,
                                            current->header.bits.IL,
                                            current->header.bits.TNF);
        ESP_LOGI(TAG,"--Payload Length: %ld", current->payload_length);
        ESP_LOGI(TAG,"--Type Length: %d", current->type_length);
        ESP_LOGI(TAG,"--Type: %.*s", (int)current->type_length, (char *)current->type);
        if (current->id) {
            ESP_LOGI(TAG,"--ID Length: %d", current->id_length);
            ESP_LOGI(TAG,"--ID: %.*s", (int)current->id_length, (char *)current->id);
        }
        if (current->lang_code) {
            ESP_LOGI(TAG,"--Language Code Length: %d", current->lang_code_length);
            ESP_LOGI(TAG,"--Language Code: %.*s", (int)current->lang_code_length, (char *)current->lang_code);
        }
        ESP_LOGI(TAG,"--Payload: %.*s", (int)current->payload_length, (char *)current->payload);
        current = current->next;
    }
}

// Function to free the linked list of NDEF records
void free_ndef_records(ndef_record *head) {
    ndef_record *current = head;
    while (current) {
        ndef_record *next = current->next;
        free(current);
        current = next;
    }
}
esp_err_t ntag_read_ndef(const rc522_handle_t rc522, const rc522_picc_t *picc)
{
    ntag_tvl_info_t ntag_tvl_info;
    ntag_get_tlv_info(rc522,picc,&ntag_tvl_info);
    if(ntag_tvl_info.blocklen <= 0 ){
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t *dataptr = (uint8_t*)malloc(ntag_tvl_info.blocklen);
    if(dataptr==NULL){
        return ESP_ERR_NO_MEM;
    }
    rc522_ntag_readn(rc522,picc,ntag_tvl_info.start_addr,dataptr,ntag_tvl_info.blocklen);

    ndef_record *records = parse_ndef_records(dataptr, ntag_tvl_info.blocklen);

    // Print the parsed records
    print_ndef_records(records);

    // Free the linked list
    free_ndef_records(records);

    free(dataptr);

    return ESP_OK;
}