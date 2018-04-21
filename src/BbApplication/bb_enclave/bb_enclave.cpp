#include "../common_enclave/common_enclave.h"
#include <stdio.h>
#include <assert.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "../GeneralSettings.h"
#include "bb_enclave_t.h"
#include "BlackBoxExecuter.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

using namespace std;

#ifdef __cplusplus
extern "C" {
#endif

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) //low_res timer
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

int recv(int sockfd, void *buf, int len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

#ifdef __cplusplus
};
#endif

void ocall_print(const char* format, uint32_t number){
    char output[500];
    memset(output,0,500);
    snprintf(output, 500, format, number);
    ocall_print(output);
}

void ocall_print(const char* str){
    #ifdef THC_DEBUG_PRINTS
    _ocall_print(str);
    #endif
}

void print_buffer(uint8_t* buffer, size_t len){
    char toPrint[len * 3 + 3];
    char* ptr = toPrint;

    snprintf(ptr++,2, "[");

    for(int i = 0; i < len; i++){
        snprintf(ptr, 4, "%02X,", (unsigned char)buffer[i]);
        ptr = ptr + 3;
    }
    
    snprintf(ptr-1, 3, "]");

    ocall_print(toPrint);
}


/*BB enclave internal data*/
uint8_t k[SECRET_KEY_SIZE_BYTES];
sgx_ec256_private_t bb_priv_key;
BlackBoxExecuter bbx;
uint32_t* graph_ids = NULL;

/***
[Initialization-step 1: input pk, attestation quote Q']
1. Verify that Q' is a valid Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode"
2. Generate an encryption key pair (bbpk, bbsk), output bbpk.
3. Compute k=DH(bbsk, pk) the shared DH key of skg and bb
4. Use the "independent attestation" mechanism to generate an Intel-signed quote that "bbpk was generated by [X-Black-Box Enclave] running in secure mode". This is Q, output.
5. Seal (k) [sealing to MRENCLAVE] and output the sealed data.
***/
sgx_status_t bb_init_1(sgx_sealed_data_t* p_sealed_data, size_t sealed_size, 
                       sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size,
                       verification_report_t* p_report, size_t report_size,
                       bb_config_t* p_config, size_t config_size) {


    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    if(!bbx.Initialize(p_config)){
        ocall_print("bb_init_1 - bbx failed to initialize");
        return status;
    }
    
    memset(k, 0, sizeof(k));

    status = verify_peer(p_report, p_skg_pk);

    if(status){
        ocall_print("verify_peer failed");
        return status;
    }

    //Compute k=DH(bbsk, pk) the shared DH key of skg and bb
    sgx_ecc_state_handle_t handle;

    status = sgx_ecc256_open_context(&handle);
    
    if(status) {
        ocall_print("sgx_ecc256_open_context status is %d\n", status);
        return status;
    }
    
    status = sgx_ecc256_create_key_pair(&bb_priv_key, p_bb_pk, handle);
    
    if(status) {
        ocall_print("sgx_ecc256_create_key_pair status is %d\n", status);
        return status;
    } 
    
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(&bb_priv_key,p_skg_pk,&shared_key, handle);
    
    if(status){
        ocall_print("sgx_ecc256_compute_shared_dhkey status is %d\n", status);
        return status;
    } 

    //shared_key is k
    memcpy(k ,&shared_key, SECRET_KEY_SIZE_BYTES);

    //Seal (k) [sealing to MRENCLAVE]
    status = sgx_seal_data(0, NULL, sizeof(k), k, sealed_size, p_sealed_data);
    
    if(status){
        ocall_print("sgx_seal_data status is %d\n", status);
        return status;
    }

    return SGX_SUCCESS;

    }

/***
[Initialization-step 2: input sealed data (k), ciphertext c']
1. Unseal k
2. Decrypt c' with k to get s
3. Seal (s) [to MRENCLAVE] and output sealed data.
***/
sgx_status_t bb_init_2(sgx_sealed_data_t* p_sealed_k,                       //in (Seal(k))
                       uint8_t* s_encrypted, size_t s_encrypted_size,       //in (c')
                       sgx_sealed_data_t* p_sealed_s, size_t sealed_size)  //out (Seal(s))
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    //Unseal k
    uint8_t k_unsealed[SECRET_KEY_SIZE_BYTES];
    uint32_t unsealed_text_length = sizeof(k_unsealed);

    status = sgx_unseal_data(p_sealed_k,
                             NULL,
                             0,
                             k_unsealed, 
                             &unsealed_text_length);
                             
    
    if(status){
        ocall_print("sgx_unseal_data status is %d\n", status);
        return status;
    }

    //TODO-remove
    //ocall_print("k=k_unsealed? %d\n", memcmp(k_unsealed, k, SECRET_KEY_SIZE_BYTES));

    uint8_t s_decrypted[SECRET_KEY_SIZE_BYTES];
    memset(s_decrypted, 0, SECRET_KEY_SIZE_BYTES);

    //Decrypt c' with k to get s
    status = decrypt(s_decrypted, SECRET_KEY_SIZE_BYTES, s_encrypted,k_unsealed);
    
    if(status){
        ocall_print("decrypt status is %d\n", status);
        return status;
    }

    if(!bbx.SetSecret(s_decrypted, SECRET_KEY_SIZE_BYTES)){
            ocall_print("bb_init_2 - failed to set secret");
            return status;
    }

    //Seal (s) [to MRENCLAVE] and output sealed data.
    status = sgx_seal_data(0, NULL, sizeof(s_decrypted), s_decrypted, sealed_size, p_sealed_s);
    
    if(status) {
        ocall_print("sgx_seal_data status is %d\n", status);
        return status;
    } 

    return SGX_SUCCESS;
}


sgx_status_t bb_re_init(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, bb_config_t* p_config, size_t config_size){

    if(!bbx.Initialize(p_config)){
        ocall_print("bb_re_init - Initialize failed");
        return SGX_ERROR_UNEXPECTED;
    }

    uint8_t s_unsealed[SECRET_KEY_SIZE_BYTES];
    uint32_t unsealed_text_length = sizeof(s_unsealed);
    sgx_status_t status;
    status = sgx_unseal_data(p_sealed_s,
                             NULL,
                             0,
                             s_unsealed, 
                             &unsealed_text_length);
                             
    
    if(status){
        ocall_print("bb_re_init - failed to unseal s, status is %d\n", status);
        return status;
    }

    if(!bbx.SetSecret(s_unsealed, SECRET_KEY_SIZE_BYTES)){
        ocall_print("bb_re_init - SetSecret failed");
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t bb_generate_first_msg(uint8_t* B_out, size_t B_out_size) {

    if(!bbx.IsReady()){
        ocall_print("bb_generate_first_msg - bbx not ready");
        return SGX_ERROR_UNEXPECTED;
    }

    if(!bbx.GenerateFirstMessage(B_out, B_out_size)){
        ocall_print("bb_generate_first_msg - failed to generate first msg");
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

/*
[Execution: input memory buffer B_in]
1. Execute B_out=X_s(B_in)
3. Output B_out
*/
sgx_status_t bb_exec(uint8_t* B_in, size_t B_in_size,                   //in (B_in)
                     uint8_t* B_out, size_t B_out_size)                 //out (B_out)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    
    if(!bbx.IsReady()){
        ocall_print("bb_exec - bbx not ready");
        return status;
    }

    ocall_print("bb_exec================");

    if(!bbx.Execute(B_in, B_in_size, B_out, B_out_size)){
        ocall_print("bb_exec - failed to execute");
        return status;
    }

    bbx.Print();

    return SGX_SUCCESS;
}

sgx_status_t derive_smk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                        sgx_ec_key_128bit_t* p_smk, size_t smk_size) {

    return _derive_smk(p_pk, pk_size, p_smk,smk_size, &bb_priv_key);

}