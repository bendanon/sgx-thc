#ifndef COMMON_ENCLAVE_H
#define COMMON_ENCLAVE_H

#include <stdio.h>
#include <assert.h>
#include "/opt/intel/sgxsdk/include/sgx_tkey_exchange.h" //#include "sgx_tkey_exchange.h"
#include "/opt/intel/sgxsdk/include/sgx_tcrypto.h" //#include "sgx_tcrypto.h"
#include "/opt/intel/sgxsdk/include/sgx_trts.h" //#include "sgx_trts.h"
#include "string.h"
#include "../GeneralSettings.h"

#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t {
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

typedef enum _derive_key_type_t {
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id,
                            sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key);

// Derive two keys from shared key and key id.
bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key,
                uint8_t key_id,
                sgx_ec_key_128bit_t *first_derived_key,
                sgx_ec_key_128bit_t *second_derived_key);
#else
#pragma message ("Default key derivation function is used.")
#endif //SUPPLIED_KEY_DERIVATION


#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context);


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API
sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

sgx_status_t encrypt_key(uint8_t* plaintext, size_t plaintext_size,  
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]);

sgx_status_t decrypt_key(uint8_t* plaintext, size_t plaintext_size,
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]);

sgx_status_t _derive_smk(sgx_ec256_public_t* p_pk, 
                         size_t pk_size, 
                         sgx_ec_key_128bit_t* p_smk, 
                         size_t smk_size, 
                         sgx_ec256_private_t* p_priv);

#endif //COMMON_ENCLAVE_H
