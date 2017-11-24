#ifndef TH_DEFINES_H
#define TH_DEFINES_H

#include <stdint.h>
#include <string.h>

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
#define SECRET_KEY_ENCRYPTED_SIZE_BYTES (SECRET_KEY_SIZE_BYTES + NIST_RECOMMANDED_IV_SIZE_BYTES + sizeof(sgx_aes_gcm_128bit_tag_t))

#define SKG_DATA_SIZE_BYTES (SECRET_KEY_SIZE_BYTES + sizeof(sgx_ec256_private_t))
#define SKG_DATA_SEALED_SIZE_BYTES 624 //sgx_calc_sealed_data_size(0,SKG_DATA_SIZE_BYTES);
#define SKG_DATA_SEALED_BASE64_SIZE_BYTES 832

#define PK_BASE64_SIZE_BYTES 88
#define REPORT_BASE64_SIZE_BYTES 512
#define KEYPOLICY_MRENCLAVE 0x0001

#define B_OUT_SIZE_BYTES 50
#define B_IN_SIZE_BYTES 50

#define IAS_URL "https://test-as.sgx.trustedservices.intel.com:443/"
#define IAS_ATTESTATION_URI "attestation/sgx/v2/"
#define IAS_REPORT_URI "report"
#define IAS_SIGRL_URI "sigrl/"

#define IAS_FULL_REPORT_URL (IAS_URL IAS_ATTESTATION_URI IAS_REPORT_URI)
#define IAS_FULL_SIGRL_URL (IAS_URL IAS_ATTESTATION_URI IAS_SIGRL_URI)

#endif //TH_DEFINES_H