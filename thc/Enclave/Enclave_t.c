#include "Enclave_t.h"

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

typedef struct ms_bb_init_1_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	sgx_ec256_public_t* ms_bb_pk;
	sgx_ec256_public_t* ms_skg_pk;
	size_t ms_pk_size;
} ms_bb_init_1_t;

typedef struct ms_skg_exec_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_bb_pk;
	sgx_ec256_public_t* ms_p_skg_pk;
	size_t ms_pk_size;
	sgx_sealed_data_t* ms_p_sealed_s_sk;
	size_t ms_sealed_size;
	uint8_t* ms_s_encrypted;
	size_t ms_s_encrypted_size;
} ms_skg_exec_t;

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
	sgx_sealed_data_t* ms_p_sealed_s;
	size_t ms_sealed_size;
	uint8_t* ms_B_in;
	size_t ms_B_in_size;
	uint8_t* ms_B_out;
	size_t ms_B_out_size;
} ms_bb_exec_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

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

static sgx_status_t SGX_CDECL sgx_bb_init_1(void* pms)
{
	ms_bb_init_1_t* ms = SGX_CAST(ms_bb_init_1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	sgx_ec256_public_t* _tmp_bb_pk = ms->ms_bb_pk;
	size_t _tmp_pk_size = ms->ms_pk_size;
	size_t _len_bb_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_bb_pk = NULL;
	sgx_ec256_public_t* _tmp_skg_pk = ms->ms_skg_pk;
	size_t _len_skg_pk = _tmp_pk_size;
	sgx_ec256_public_t* _in_skg_pk = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_bb_init_1_t));
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_bb_pk, _len_bb_pk);
	CHECK_UNIQUE_POINTER(_tmp_skg_pk, _len_skg_pk);

	if (_tmp_sealed_data != NULL) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	if (_tmp_bb_pk != NULL) {
		if ((_in_bb_pk = (sgx_ec256_public_t*)malloc(_len_bb_pk)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bb_pk, 0, _len_bb_pk);
	}
	if (_tmp_skg_pk != NULL) {
		_in_skg_pk = (sgx_ec256_public_t*)malloc(_len_skg_pk);
		if (_in_skg_pk == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_skg_pk, _tmp_skg_pk, _len_skg_pk);
	}
	ms->ms_retval = bb_init_1(_in_sealed_data, _tmp_sealed_size, _in_bb_pk, _in_skg_pk, _tmp_pk_size);
err:
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}
	if (_in_bb_pk) {
		memcpy(_tmp_bb_pk, _in_bb_pk, _len_bb_pk);
		free(_in_bb_pk);
	}
	if (_in_skg_pk) free(_in_skg_pk);

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
	ms->ms_retval = skg_exec(_in_p_bb_pk, _in_p_skg_pk, _tmp_pk_size, _in_p_sealed_s_sk, _tmp_sealed_size, _in_s_encrypted, _tmp_s_encrypted_size);
err:
	if (_in_p_bb_pk) free(_in_p_bb_pk);
	if (_in_p_skg_pk) free(_in_p_skg_pk);
	if (_in_p_sealed_s_sk) free(_in_p_sealed_s_sk);
	if (_in_s_encrypted) {
		memcpy(_tmp_s_encrypted, _in_s_encrypted, _len_s_encrypted);
		free(_in_s_encrypted);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_bb_init_2(void* pms)
{
	ms_bb_init_2_t* ms = SGX_CAST(ms_bb_init_2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_p_sealed_k = ms->ms_p_sealed_k;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_p_sealed_k = _tmp_sealed_size;
	sgx_sealed_data_t* _in_p_sealed_k = NULL;
	uint8_t* _tmp_s_encrypted = ms->ms_s_encrypted;
	size_t _tmp_s_encrypted_size = ms->ms_s_encrypted_size;
	size_t _len_s_encrypted = _tmp_s_encrypted_size;
	uint8_t* _in_s_encrypted = NULL;
	sgx_sealed_data_t* _tmp_p_sealed_s = ms->ms_p_sealed_s;
	size_t _len_p_sealed_s = _tmp_sealed_size;
	sgx_sealed_data_t* _in_p_sealed_s = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_bb_init_2_t));
	CHECK_UNIQUE_POINTER(_tmp_p_sealed_k, _len_p_sealed_k);
	CHECK_UNIQUE_POINTER(_tmp_s_encrypted, _len_s_encrypted);
	CHECK_UNIQUE_POINTER(_tmp_p_sealed_s, _len_p_sealed_s);

	if (_tmp_p_sealed_k != NULL) {
		_in_p_sealed_k = (sgx_sealed_data_t*)malloc(_len_p_sealed_k);
		if (_in_p_sealed_k == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_sealed_k, _tmp_p_sealed_k, _len_p_sealed_k);
	}
	if (_tmp_s_encrypted != NULL) {
		_in_s_encrypted = (uint8_t*)malloc(_len_s_encrypted);
		if (_in_s_encrypted == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_s_encrypted, _tmp_s_encrypted, _len_s_encrypted);
	}
	if (_tmp_p_sealed_s != NULL) {
		if ((_in_p_sealed_s = (sgx_sealed_data_t*)malloc(_len_p_sealed_s)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_sealed_s, 0, _len_p_sealed_s);
	}
	ms->ms_retval = bb_init_2(_in_p_sealed_k, _in_s_encrypted, _tmp_s_encrypted_size, _in_p_sealed_s, _tmp_sealed_size);
err:
	if (_in_p_sealed_k) free(_in_p_sealed_k);
	if (_in_s_encrypted) free(_in_s_encrypted);
	if (_in_p_sealed_s) {
		memcpy(_tmp_p_sealed_s, _in_p_sealed_s, _len_p_sealed_s);
		free(_in_p_sealed_s);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_bb_exec(void* pms)
{
	ms_bb_exec_t* ms = SGX_CAST(ms_bb_exec_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_p_sealed_s = ms->ms_p_sealed_s;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_p_sealed_s = _tmp_sealed_size;
	sgx_sealed_data_t* _in_p_sealed_s = NULL;
	uint8_t* _tmp_B_in = ms->ms_B_in;
	size_t _tmp_B_in_size = ms->ms_B_in_size;
	size_t _len_B_in = _tmp_B_in_size;
	uint8_t* _in_B_in = NULL;
	uint8_t* _tmp_B_out = ms->ms_B_out;
	size_t _tmp_B_out_size = ms->ms_B_out_size;
	size_t _len_B_out = _tmp_B_out_size;
	uint8_t* _in_B_out = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_bb_exec_t));
	CHECK_UNIQUE_POINTER(_tmp_p_sealed_s, _len_p_sealed_s);
	CHECK_UNIQUE_POINTER(_tmp_B_in, _len_B_in);
	CHECK_UNIQUE_POINTER(_tmp_B_out, _len_B_out);

	if (_tmp_p_sealed_s != NULL) {
		_in_p_sealed_s = (sgx_sealed_data_t*)malloc(_len_p_sealed_s);
		if (_in_p_sealed_s == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_sealed_s, _tmp_p_sealed_s, _len_p_sealed_s);
	}
	if (_tmp_B_in != NULL) {
		_in_B_in = (uint8_t*)malloc(_len_B_in);
		if (_in_B_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_B_in, _tmp_B_in, _len_B_in);
	}
	if (_tmp_B_out != NULL) {
		if ((_in_B_out = (uint8_t*)malloc(_len_B_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_B_out, 0, _len_B_out);
	}
	ms->ms_retval = bb_exec(_in_p_sealed_s, _tmp_sealed_size, _in_B_in, _tmp_B_in_size, _in_B_out, _tmp_B_out_size);
err:
	if (_in_p_sealed_s) free(_in_p_sealed_s);
	if (_in_B_in) free(_in_B_in);
	if (_in_B_out) {
		memcpy(_tmp_B_out, _in_B_out, _len_B_out);
		free(_in_B_out);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	if (_tmp_plaintext != NULL) {
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_plaintext, _tmp_plaintext, _len_plaintext);
	}
	if (_tmp_sealed_data != NULL) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	ms->ms_retval = seal(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	uint32_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	if (_tmp_sealed_data != NULL) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_plaintext != NULL) {
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	ms->ms_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_plaintext, _tmp_plaintext_len);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) {
		memcpy(_tmp_plaintext, _in_plaintext, _len_plaintext);
		free(_in_plaintext);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_skg_init, 0},
		{(void*)(uintptr_t)sgx_bb_init_1, 0},
		{(void*)(uintptr_t)sgx_skg_exec, 0},
		{(void*)(uintptr_t)sgx_bb_init_2, 0},
		{(void*)(uintptr_t)sgx_bb_exec, 0},
		{(void*)(uintptr_t)sgx_seal, 0},
		{(void*)(uintptr_t)sgx_unseal, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][7];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

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

