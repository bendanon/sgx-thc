#ifndef ISV_ENCLAVE_T_H__
#define ISV_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"
#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t verify_secret_data(sgx_ra_context_t context, uint8_t* p_secret, uint32_t secret_size, uint8_t* gcm_mac, uint32_t max_verification_length, uint8_t* p_ret);
sgx_status_t skg_init(sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* pk, size_t pk_size);
sgx_status_t derive_smk(sgx_ec256_public_t* pk, size_t pk_size, sgx_ec_key_128bit_t* smk, size_t smk_size);
sgx_status_t bb_init_1(sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, size_t pk_size);
sgx_status_t skg_exec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size, sgx_sealed_data_t* p_sealed_s_sk, size_t sealed_size, uint8_t* s_encrypted, size_t s_encrypted_size);
sgx_status_t bb_init_2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, size_t sealed_size);
sgx_status_t bb_exec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
