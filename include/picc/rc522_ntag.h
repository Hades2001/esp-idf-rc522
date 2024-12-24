#pragma once

#include "rc522_types.h"
#include "rc522_picc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NTAG_PAGE_SIZE  (4)
#define NTAG_TVL_FIND_SIZE   (4)
#define NTAG_PAGE_READ_SIZE (16)

typedef struct ntag_tvl_info{
    uint8_t type;
    int blocklen;
    int start_addr;
}ntag_tvl_info_t;

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


esp_err_t rc522_ntag_read(const rc522_handle_t rc522, const rc522_picc_t *picc, uint8_t block_address,uint8_t out_buffer[NTAG_PAGE_SIZE]);
esp_err_t rc522_ntag_readn(const rc522_handle_t rc522, const rc522_picc_t *picc, uint16_t address,uint8_t* out_buffer,int len);

NDEFHeader parse_header(uint8_t byte);
ndef_record *create_ndef_record(NDEFHeader header, uint32_t payload_length, uint8_t type_length, uint8_t id_length, uint8_t lang_code_length, uint8_t *lang_code, uint8_t *type, uint8_t *id, uint8_t *payload);
ndef_record *parse_ndef_records(uint8_t *data, size_t length);
void print_ndef_records(ndef_record *head);
void free_ndef_records(ndef_record *head);
esp_err_t ntag_read_ndef(const rc522_handle_t rc522, const rc522_picc_t *picc, uint8_t **dataptr, ndef_record **records);

#ifdef __cplusplus
}
#endif
