#include "bb_enclave_u.h"
#include <errno.h>

typedef struct ms_bb_init_1_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	sgx_ec256_public_t* ms_bb_pk;
	sgx_ec256_public_t* ms_skg_pk;
	size_t ms_pk_size;
	uint32_t ms_num_of_neighbors;
	uint32_t ms_num_of_vertices;
} ms_bb_init_1_t;

typedef struct ms_bb_init_2_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_p_sealed_k;
	uint8_t* ms_s_encrypted;
	size_t ms_s_encrypted_size;
	sgx_sealed_data_t* ms_p_sealed_s;
	size_t ms_sealed_size;
} ms_bb_init_2_t;

typedef struct ms_bb_exec_t {
	sgx_status_t ms_retval;
	uint8_t* ms_B_in;
	size_t ms_B_in_size;
	uint8_t* ms_B_out;
	size_t ms_B_out_size;
} ms_bb_exec_t;

typedef struct ms_bb_generate_first_msg_t {
	sgx_status_t ms_retval;
	uint8_t* ms_B_out;
	size_t ms_B_out_size;
} ms_bb_generate_first_msg_t;

typedef struct ms_bb_get_result_t {
	sgx_status_t ms_retval;
	uint8_t* ms_B_out;
	size_t ms_B_out_size;
} ms_bb_get_result_t;

typedef struct ms_bb_re_init_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_p_sealed_s;
	size_t ms_sealed_size;
	uint32_t ms_num_of_neighbors;
	uint32_t ms_num_of_vertices;
} ms_bb_re_init_t;

typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_derive_smk_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_pk;
	size_t ms_pk_size;
	sgx_ec_key_128bit_t* ms_smk;
	size_t ms_smk_size;
} ms_derive_smk_t;

typedef struct ms_verify_peer_t {
	sgx_status_t ms_retval;
	unsigned char* ms_reportBody;
	size_t ms_reportBody_size;
	unsigned char* ms_chain;
	size_t ms_chain_size;
	unsigned char* ms_signature;
	size_t ms_signature_size;
	sgx_ec256_public_t* ms_peer_pk;
	sgx_ec256_public_t* ms_unusable_pk;
	size_t ms_pk_size;
} ms_verify_peer_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL bb_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL bb_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[15];
} ocall_table_bb_enclave = {
	15,
	{
		(void*)bb_enclave_ocall_print,
		(void*)bb_enclave_ocall_print_string,
		(void*)bb_enclave_ocall_current_time,
		(void*)bb_enclave_ocall_low_res_time,
		(void*)bb_enclave_ocall_recv,
		(void*)bb_enclave_ocall_send,
		(void*)bb_enclave_create_session_ocall,
		(void*)bb_enclave_exchange_report_ocall,
		(void*)bb_enclave_close_session_ocall,
		(void*)bb_enclave_invoke_service_ocall,
		(void*)bb_enclave_sgx_oc_cpuidex,
		(void*)bb_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)bb_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)bb_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)bb_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t bb_init_1(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, size_t pk_size, uint32_t num_of_neighbors, uint32_t num_of_vertices)
{
	sgx_status_t status;
	ms_bb_init_1_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_bb_pk = bb_pk;
	ms.ms_skg_pk = skg_pk;
	ms.ms_pk_size = pk_size;
	ms.ms_num_of_neighbors = num_of_neighbors;
	ms.ms_num_of_vertices = num_of_vertices;
	status = sgx_ecall(eid, 0, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_init_2(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, size_t sealed_size)
{
	sgx_status_t status;
	ms_bb_init_2_t ms;
	ms.ms_p_sealed_k = p_sealed_k;
	ms.ms_s_encrypted = s_encrypted;
	ms.ms_s_encrypted_size = s_encrypted_size;
	ms.ms_p_sealed_s = p_sealed_s;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 1, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_exec(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size)
{
	sgx_status_t status;
	ms_bb_exec_t ms;
	ms.ms_B_in = B_in;
	ms.ms_B_in_size = B_in_size;
	ms.ms_B_out = B_out;
	ms.ms_B_out_size = B_out_size;
	status = sgx_ecall(eid, 2, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_generate_first_msg(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* B_out, size_t B_out_size)
{
	sgx_status_t status;
	ms_bb_generate_first_msg_t ms;
	ms.ms_B_out = B_out;
	ms.ms_B_out_size = B_out_size;
	status = sgx_ecall(eid, 3, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_get_result(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* B_out, size_t B_out_size)
{
	sgx_status_t status;
	ms_bb_get_result_t ms;
	ms.ms_B_out = B_out;
	ms.ms_B_out_size = B_out_size;
	status = sgx_ecall(eid, 4, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_re_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* p_sealed_s, size_t sealed_size, uint32_t num_of_neighbors, uint32_t num_of_vertices)
{
	sgx_status_t status;
	ms_bb_re_init_t ms;
	ms.ms_p_sealed_s = p_sealed_s;
	ms.ms_sealed_size = sealed_size;
	ms.ms_num_of_neighbors = num_of_neighbors;
	ms.ms_num_of_vertices = num_of_vertices;
	status = sgx_ecall(eid, 5, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 6, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 7, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t derive_smk(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* pk, size_t pk_size, sgx_ec_key_128bit_t* smk, size_t smk_size)
{
	sgx_status_t status;
	ms_derive_smk_t ms;
	ms.ms_pk = pk;
	ms.ms_pk_size = pk_size;
	ms.ms_smk = smk;
	ms.ms_smk_size = smk_size;
	status = sgx_ecall(eid, 8, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_peer(sgx_enclave_id_t eid, sgx_status_t* retval, unsigned char* reportBody, size_t reportBody_size, unsigned char* chain, size_t chain_size, unsigned char* signature, size_t signature_size, sgx_ec256_public_t* peer_pk, sgx_ec256_public_t* unusable_pk, size_t pk_size)
{
	sgx_status_t status;
	ms_verify_peer_t ms;
	ms.ms_reportBody = reportBody;
	ms.ms_reportBody_size = reportBody_size;
	ms.ms_chain = chain;
	ms.ms_chain_size = chain_size;
	ms.ms_signature = signature;
	ms.ms_signature_size = signature_size;
	ms.ms_peer_pk = peer_pk;
	ms.ms_unusable_pk = unusable_pk;
	ms.ms_pk_size = pk_size;
	status = sgx_ecall(eid, 9, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 10, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 11, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 12, &ocall_table_bb_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

