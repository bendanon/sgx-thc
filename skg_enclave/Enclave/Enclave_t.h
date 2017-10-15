#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_uae_service.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t skg_init(sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* pk, size_t pk_size, sgx_target_info_t* target_info, sgx_report_t* p_report);
sgx_status_t bb_init_1(sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, size_t pk_size, uint8_t* k_encrypted, size_t k_encrypted_size, sgx_target_info_t* target_info, sgx_report_t* p_report);
sgx_status_t skg_exec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size, uint8_t* k_encrypted, size_t k_encrypted_size, sgx_sealed_data_t* p_sealed_s_sk, size_t sealed_size, uint8_t* s_encrypted, size_t s_encrypted_size);
sgx_status_t bb_init_2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, size_t sealed_size);
sgx_status_t bb_exec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size);
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
