#include "skg_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_skg_init_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	sgx_ec256_public_t* ms_pk;
	size_t ms_pk_size;
} ms_skg_init_t;

typedef struct ms_skg_exec_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_bb_pk;
	sgx_ec256_public_t* ms_p_skg_pk;
	size_t ms_pk_size;
	verification_report_t* ms_p_report;
	size_t ms_report_size;
	sgx_sealed_data_t* ms_p_sealed_s_sk;
	size_t ms_sealed_size;
	uint8_t* ms_s_encrypted;
	size_t ms_s_encrypted_size;
} ms_skg_exec_t;

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

typedef struct ms__ocall_print_t {
	char* ms_str;
} ms__ocall_print_t;

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

static sgx_status_t SGX_CDECL sgx_skg_init(void* pms)
{
	ms_skg_init_t* ms = SGX_CAST(ms_skg_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	sgx_ec256_public_t* _tmp_pk = ms->ms_pk;
	size_t _tmp_pk_size = ms->ms_pk_size;
	size_t _len_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_pk = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_skg_init_t));
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_pk, _len_pk);

	if (_tmp_sealed_data != NULL) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	if (_tmp_pk != NULL) {
		if ((_in_pk = (sgx_ec256_public_t*)malloc(_len_pk)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pk, 0, _len_pk);
	}
	ms->ms_retval = skg_init(_in_sealed_data, _tmp_sealed_size, _in_pk, _tmp_pk_size);
err:
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}
	if (_in_pk) {
		memcpy(_tmp_pk, _in_pk, _len_pk);
		free(_in_pk);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_skg_exec(void* pms)
{
	ms_skg_exec_t* ms = SGX_CAST(ms_skg_exec_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_p_bb_pk = ms->ms_p_bb_pk;
	size_t _tmp_pk_size = ms->ms_pk_size;
	size_t _len_p_bb_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_p_bb_pk = NULL;
	sgx_ec256_public_t* _tmp_p_skg_pk = ms->ms_p_skg_pk;
	size_t _len_p_skg_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_p_skg_pk = NULL;
	verification_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _tmp_report_size = ms->ms_report_size;
	size_t _len_p_report = _tmp_report_size;
	verification_report_t* _in_p_report = NULL;
	sgx_sealed_data_t* _tmp_p_sealed_s_sk = ms->ms_p_sealed_s_sk;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_p_sealed_s_sk = _tmp_sealed_size;
	sgx_sealed_data_t* _in_p_sealed_s_sk = NULL;
	uint8_t* _tmp_s_encrypted = ms->ms_s_encrypted;
	size_t _tmp_s_encrypted_size = ms->ms_s_encrypted_size;
	size_t _len_s_encrypted = _tmp_s_encrypted_size;
	uint8_t* _in_s_encrypted = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_skg_exec_t));
	CHECK_UNIQUE_POINTER(_tmp_p_bb_pk, _len_p_bb_pk);
	CHECK_UNIQUE_POINTER(_tmp_p_skg_pk, _len_p_skg_pk);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_sealed_s_sk, _len_p_sealed_s_sk);
	CHECK_UNIQUE_POINTER(_tmp_s_encrypted, _len_s_encrypted);

	if (_tmp_p_bb_pk != NULL) {
		_in_p_bb_pk = (sgx_ec256_public_t*)malloc(_len_p_bb_pk);
		if (_in_p_bb_pk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_bb_pk, _tmp_p_bb_pk, _len_p_bb_pk);
	}
	if (_tmp_p_skg_pk != NULL) {
		_in_p_skg_pk = (sgx_ec256_public_t*)malloc(_len_p_skg_pk);
		if (_in_p_skg_pk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_skg_pk, _tmp_p_skg_pk, _len_p_skg_pk);
	}
	if (_tmp_p_report != NULL) {
		_in_p_report = (verification_report_t*)malloc(_len_p_report);
		if (_in_p_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_report, _tmp_p_report, _len_p_report);
	}
	if (_tmp_p_sealed_s_sk != NULL) {
		_in_p_sealed_s_sk = (sgx_sealed_data_t*)malloc(_len_p_sealed_s_sk);
		if (_in_p_sealed_s_sk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_sealed_s_sk, _tmp_p_sealed_s_sk, _len_p_sealed_s_sk);
	}
	if (_tmp_s_encrypted != NULL) {
		if ((_in_s_encrypted = (uint8_t*)malloc(_len_s_encrypted)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_s_encrypted, 0, _len_s_encrypted);
	}
	ms->ms_retval = skg_exec(_in_p_bb_pk, _in_p_skg_pk, _tmp_pk_size, _in_p_report, _tmp_report_size, _in_p_sealed_s_sk, _tmp_sealed_size, _in_s_encrypted, _tmp_s_encrypted_size);
err:
	if (_in_p_bb_pk) free(_in_p_bb_pk);
	if (_in_p_skg_pk) free(_in_p_skg_pk);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_sealed_s_sk) free(_in_p_sealed_s_sk);
	if (_in_s_encrypted) {
		memcpy(_tmp_s_encrypted, _in_s_encrypted, _len_s_encrypted);
		free(_in_s_encrypted);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = enclave_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));

	ms->ms_retval = enclave_ra_close(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_derive_smk(void* pms)
{
	ms_derive_smk_t* ms = SGX_CAST(ms_derive_smk_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_pk = ms->ms_pk;
	size_t _tmp_pk_size = ms->ms_pk_size;
	size_t _len_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_pk = NULL;
	sgx_ec_key_128bit_t* _tmp_smk = ms->ms_smk;
	size_t _tmp_smk_size = ms->ms_smk_size;
	size_t _len_smk = _tmp_smk_size;
	sgx_ec_key_128bit_t* _in_smk = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_derive_smk_t));
	CHECK_UNIQUE_POINTER(_tmp_pk, _len_pk);
	CHECK_UNIQUE_POINTER(_tmp_smk, _len_smk);

	if (_tmp_pk != NULL) {
		_in_pk = (sgx_ec256_public_t*)malloc(_len_pk);
		if (_in_pk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_pk, _tmp_pk, _len_pk);
	}
	if (_tmp_smk != NULL) {
		if ((_in_smk = (sgx_ec_key_128bit_t*)malloc(_len_smk)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_smk, 0, _len_smk);
	}
	ms->ms_retval = derive_smk(_in_pk, _tmp_pk_size, _in_smk, _tmp_smk_size);
err:
	if (_in_pk) free(_in_pk);
	if (_in_smk) {
		memcpy(_tmp_smk, _in_smk, _len_smk);
		free(_in_smk);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_skg_init, 0},
		{(void*)(uintptr_t)sgx_skg_exec, 0},
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0},
		{(void*)(uintptr_t)sgx_derive_smk, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[15][8];
} g_dyn_entry_table = {
	15,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL _ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms__ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms__ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms__ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms__ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_current_time(double* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(*time);

	ms_ocall_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_current_time_t);
	void *__tmp = NULL;

	ocalloc_size += (time != NULL && sgx_is_within_enclave(time, _len_time)) ? _len_time : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_current_time_t));

	if (time != NULL && sgx_is_within_enclave(time, _len_time)) {
		ms->ms_time = (double*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_time);
		memset(ms->ms_time, 0, _len_time);
	} else if (time == NULL) {
		ms->ms_time = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (time) memcpy((void*)time, ms->ms_time, _len_time);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_low_res_time(int* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(*time);

	ms_ocall_low_res_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_low_res_time_t);
	void *__tmp = NULL;

	ocalloc_size += (time != NULL && sgx_is_within_enclave(time, _len_time)) ? _len_time : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_low_res_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_low_res_time_t));

	if (time != NULL && sgx_is_within_enclave(time, _len_time)) {
		ms->ms_time = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_time);
		memset(ms->ms_time, 0, _len_time);
	} else if (time == NULL) {
		ms->ms_time = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (time) memcpy((void*)time, ms->ms_time, _len_time);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));

	ms->ms_sockfd = sockfd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);
	errno = ms->ocall_errno;
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));

	ms->ms_sockfd = sockfd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	errno = ms->ocall_errno;
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(10, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

