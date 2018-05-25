#ifndef TH_DEFINES_H
#define TH_DEFINES_H

#include <stdint.h>
#include <string.h>
#include <cmath>
#include "thc_ecall_types.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define SECRET_KEY_SIZE_BYTES 32
#define SECRET_KEY_SEALED_SIZE_BYTES 592 //sgx_calc_sealed_data_size(0,SECRET_KEY_SIZE_BYTES);
#define SECRET_KEY_SEALED_BASE64_SIZE_BYTES 792

#define NIST_RECOMMANDED_IV_SIZE_BYTES 12
//#define AES_GCM_AUX_SIZE (NIST_RECOMMANDED_IV_SIZE_BYTES + sizeof(sgx_aes_gcm_128bit_tag_t))
#define AES_GCM_AUX_SIZE (NIST_RECOMMANDED_IV_SIZE_BYTES + 16)
#define PLAINTEXT_SIZE_OF(CIPHERTEXT_SIZE) (CIPHERTEXT_SIZE - AES_GCM_AUX_SIZE)
#define CIPHERTEXT_SIZE_OF(PLAINTEXT_SIZE) (PLAINTEXT_SIZE + AES_GCM_AUX_SIZE)
#define SECRET_KEY_ENCRYPTED_SIZE_BYTES (CIPHERTEXT_SIZE_OF(SECRET_KEY_SIZE_BYTES))


#define MAX_GRAPH_SIZE 10000
#define EDGE_PRINT_SIZE_BYTES sizeof("[10000,10000]") /*according to MAX_GRAPH_SIZE*/

#define THC_MSG_HEADER_SIZE (20 + sizeof("255.255.255.255:99999999"))
#define THC_MAX_NUM_OF_TRIES 3
#define THC_SLEEP_BETWEEN_RETRIES_SECONDS 3

#define THC_ACK_MSG_STRING "ACK"
#define MAX_UINT32 ((uint32_t) 0-1)
#define PARTY_ID_SIZE_BYTES (128 / 8)
#define APP_PARTY_PARAMS_SIZE_BYTES (sizeof(APP_PARAMETER_DATA_TYPE)*APP_NUM_OF_PARAMETERS)
#define APP_PARTY_FULL_SIZE_BYTES (PARTY_ID_SIZE_BYTES+APP_PARTY_PARAMS_SIZE_BYTES+MAX_EMAIL_SIZE_BYTES)
#define EDGE_SIZE_BYTES (sizeof(uint32_t)*2)
#define THC_MAX_NUMBER_OF_ROUNDS(GRAPH_SIZE) (GRAPH_SIZE + GRAPH_SIZE*GRAPH_SIZE)
#define THC_ROUND_NUMBER_SIZE_BYTES sizeof(uint32_t)
#define VERTICES_LEN_SIZE_BYTES sizeof(uint32_t)
#define EDGES_LEN_SIZE_BYTES sizeof(uint32_t)
#define THC_MSG_TYPE_SIZE_BYTES sizeof(uint32_t)

/*
V <= MAX_NEIGHBORS(V) ---> MAX_EDGES(V) = V(V-1)/2
V > MAX_NEIGHBORS(V) ---> MAX_EDGES(V) = MAX_NEIGHBORS(V)*V

In the second case there might be a tighter bound, 
therefore if MAX_NEIGHBORS(V) is O(V) you might want to change MAX_EDGES to V(V-1)/2 or to a tighter bound

MAX_EDGES(V) = MIN(V(V-1)/2, MAX_NEIGHBORS(V)*V)
*/

#define MAX_NEIGHBORS(V) (V-1)
constexpr int MAX_EDGES(int V)
{
    return (V*(V-1)/2) <= (MAX_NEIGHBORS(V)*V) ? (V*(V-1)/2) : (MAX_NEIGHBORS(V)*V);
}
#define THC_PLAIN_MSG_SIZE_BYTES(GRAPH_SIZE) (THC_MSG_TYPE_SIZE_BYTES + \
                                  THC_ROUND_NUMBER_SIZE_BYTES + \
                                  APP_PARTY_FULL_SIZE_BYTES + \
                                  VERTICES_LEN_SIZE_BYTES + \
                                  (GRAPH_SIZE*(APP_PARTY_FULL_SIZE_BYTES)) + \
                                  EDGES_LEN_SIZE_BYTES + \
                                  (MAX_EDGES(GRAPH_SIZE)*EDGE_SIZE_BYTES))

#define ABORT_MESSAGE "ABORT"
#define RESULT_CANARY "RESULT,"
#define NO_MATCH_STRING "NO MATCH"
#define REAULT_EMAIL_DELIMITER ", "
#define THC_ENCRYPTED_MSG_SIZE_BYTES(GRAPH_SIZE) (CIPHERTEXT_SIZE_OF(THC_PLAIN_MSG_SIZE_BYTES(GRAPH_SIZE)))

#define SKG_DATA_SIZE_BYTES (SECRET_KEY_SIZE_BYTES + sizeof(sgx_ec256_private_t))
#define SKG_DATA_SEALED_SIZE_BYTES 624 //sgx_calc_sealed_data_size(0,SKG_DATA_SIZE_BYTES);
#define SKG_DATA_SEALED_BASE64_SIZE_BYTES 832

#define PK_BASE64_SIZE_BYTES 88
#define REPORT_BASE64_SIZE_BYTES 512
#define KEYPOLICY_MRENCLAVE 0x0001

#define IAS_URL "https://test-as.sgx.trustedservices.intel.com:443/"
#define IAS_ATTESTATION_URI "attestation/sgx/v2/"
#define IAS_REPORT_URI "report"
#define IAS_SIGRL_URI "sigrl/"

#define IAS_FULL_REPORT_URL (IAS_URL IAS_ATTESTATION_URI IAS_REPORT_URI)
#define IAS_FULL_SIGRL_URL (IAS_URL IAS_ATTESTATION_URI IAS_SIGRL_URI)

#define SIGNATURE_LENGTH_BYTES 256
#define MAX_CERT_SIZE 16384

//#define THC_DEBUG_PRINTS
#define SCHIZZO_TEST

#endif //TH_DEFINES_H