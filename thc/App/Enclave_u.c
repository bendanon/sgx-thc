#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t skg_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* pk, size_t pk_size)
{
	sgx_status_t status;
	ms_skg_init_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_pk = pk;
	ms.ms_pk_size = pk_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_init_1(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, size_t pk_size)
{
	sgx_status_t status;
	ms_bb_init_1_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_bb_pk = bb_pk;
	ms.ms_skg_pk = skg_pk;
	ms.ms_pk_size = pk_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t skg_exec(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size, sgx_sealed_data_t* p_sealed_s_sk, size_t sealed_size, uint8_t* s_encrypted, size_t s_encrypted_size)
{
	sgx_status_t status;
	ms_skg_exec_t ms;
	ms.ms_p_bb_pk = p_bb_pk;
	ms.ms_p_skg_pk = p_skg_pk;
	ms.ms_pk_size = pk_size;
	ms.ms_p_sealed_s_sk = p_sealed_s_sk;
	ms.ms_sealed_size = sealed_size;
	ms.ms_s_encrypted = s_encrypted;
	ms.ms_s_encrypted_size = s_encrypted_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t bb_exec(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* p_sealed_s, size_t sealed_size, uint8_t* B_in, size_t B_in_size, uint8_t* B_out, size_t B_out_size)
{
	sgx_status_t status;
	ms_bb_exec_t ms;
	ms.ms_p_sealed_s = p_sealed_s;
	ms.ms_sealed_size = sealed_size;
	ms.ms_B_in = B_in;
	ms.ms_B_in_size = B_in_size;
	ms.ms_B_out = B_out;
	ms.ms_B_out_size = B_out_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len)
{
	sgx_status_t status;
	ms_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

