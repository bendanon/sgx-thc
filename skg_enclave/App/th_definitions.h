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

#define NIST_RECOMMANDED_IV_SIZE_BYTES 12
#define SECRET_KEY_ENCRYPTED_SIZE_BYTES (SECRET_KEY_SIZE_BYTES + NIST_RECOMMANDED_IV_SIZE_BYTES + sizeof(sgx_aes_gcm_128bit_tag_t))

#define SKG_DATA_SIZE_BYTES (SECRET_KEY_SIZE_BYTES + sizeof(sgx_ec256_private_t))
#define SKG_DATA_SEALED_SIZE_BYTES 624 //sgx_calc_sealed_data_size(0,SKG_DATA_SIZE_BYTES);

#define KEYPOLICY_MRENCLAVE 0x0001

#define B_OUT_SIZE_BYTES 50
#define B_IN_SIZE_BYTES 50

#endif //TH_DEFINES_H