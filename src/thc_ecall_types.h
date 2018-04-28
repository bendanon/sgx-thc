#ifndef BB_CONFIG_T_H
#define BB_CONFIG_T_H

#define APP_PARAMETER_DATA_TYPE uint8_t
#define PARAM_T APP_PARAMETER_DATA_TYPE
#define APP_NUM_OF_PARAMETERS 4
#define MAX_EMAIL_SIZE_BYTES 35
#define MIN_EMAIL_SIZE_BYTES 6

typedef struct _bb_config_t {
    uint32_t num_of_neighbors;
    uint32_t num_of_vertices;
    char    email[MAX_EMAIL_SIZE_BYTES];
    PARAM_T params[APP_NUM_OF_PARAMETERS];
} bb_config_t;


#define RA_MAX_RESPONSE_BODY_SIZE_BYTES 1000
#define RA_MAX_CERT_CHAIN_SIZE_BYTES 10000
#define RA_SIGNATURE_SIZE_BYTES 256
#define RA_PUBLIC_KEY_SIZE_BYTES 64 /*taken from sgx_ec256_public_t*/

typedef struct _verification_report_t {

    uint8_t response_body[RA_MAX_RESPONSE_BODY_SIZE_BYTES];
    size_t response_body_size;

    uint8_t cert_chain[RA_MAX_CERT_CHAIN_SIZE_BYTES];
    size_t cert_chain_size;

    uint8_t signature[RA_SIGNATURE_SIZE_BYTES];

    uint8_t unusable_pk[RA_PUBLIC_KEY_SIZE_BYTES];

} verification_report_t;

#endif