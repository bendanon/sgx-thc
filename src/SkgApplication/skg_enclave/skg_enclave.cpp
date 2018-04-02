#include "../common_enclave/common_enclave.h"
#include <assert.h>
#include "skg_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "../GeneralSettings.h"

/*SKG enclave internal data*/
uint8_t s_sk[SKG_DATA_SIZE_BYTES];
sgx_ec256_private_t skg_priv_key;

void ocall_print(const char* format, uint32_t number){
    char output[50];
    memset(output,0,50);
    snprintf(output, 50, format, number);
    ocall_print(output);
}

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

/***
[Initialization: no input] - *SKG ENCLAVE CODE*
1. Use SGX hardware randomness to generate shared secret key s
2. Generate an encryption key pair (pk,sk), output pk.
3. Use the "independent attestation" mechanism to generate an Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode". This is Q’, output.
4. Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data. output.
***/
sgx_status_t skg_init(sgx_sealed_data_t* p_sealed_data, size_t sealed_size, 
                      sgx_ec256_public_t* p_pk,size_t pk_size) {
    
        memset(s_sk, 0, sizeof(s_sk));        
        sgx_status_t status = SGX_ERROR_UNEXPECTED;

        //Use SGX hardware randomness to generate shared secret key s
        status = sgx_read_rand((unsigned char*)s_sk, SECRET_KEY_SIZE_BYTES);        
        
        if(status) {
            ocall_print("sgx_read_rand status is %d\n", status);
            return status;
        } 
        
        //Generate an encryption key pair (pk,sk), output pk
        sgx_ecc_state_handle_t handle;
    
        status = sgx_ecc256_open_context(&handle);
        
        if(status) {
            ocall_print("sgx_ecc256_open_context status is %d\n", status);
            return status;
        } 
        
        status = sgx_ecc256_create_key_pair(&skg_priv_key, p_pk, handle);

        
        if(status) {
            return status;
            ocall_print("sgx_ecc256_create_key_pair status is %d\n", status);
        } 
        
        memcpy(s_sk + SECRET_KEY_SIZE_BYTES, &skg_priv_key, sizeof(sgx_ec256_private_t));

        //Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data.        
        status = sgx_seal_data(0, NULL, sizeof(s_sk), s_sk, sealed_size, p_sealed_data);
        
        if(status){
            ocall_print("sgx_seal_data status is %d\n", status);
            return status;
        } 

        return SGX_SUCCESS;
    }

/***
[Execution: input pk, sealed data (s,sk), bb-public bbpk , an attestation quote Q]
1. Verify that Q is a valid Intel-signed quote of the form "c was generated by [X-Black-Box Enclave] running in secure mode"
2. Unseal s,sk (verify that pk matches sk)
3. Compute a symmetric encryption key k using pk and bbpk 
4. Compute and output c'=E_k(s) --- the (symmetric) encryption of s under k
***/
sgx_status_t skg_exec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size,  //in (bbpk, pk)
                      sgx_sealed_data_t* p_sealed_s_sk, size_t sealed_size, //in (Seal(s,sk))                                            
                      uint8_t* s_encrypted, size_t s_encrypted_size)         //out (c')
{

    sgx_status_t status = SGX_ERROR_UNEXPECTED;
  
    //Unseal s,sk
    uint8_t s_sk_unsealed[SKG_DATA_SIZE_BYTES];
    uint32_t unsealed_text_length = SKG_DATA_SIZE_BYTES;

    status = sgx_unseal_data(p_sealed_s_sk,
                             NULL,
                             0,
                             s_sk_unsealed, 
                             &unsealed_text_length);
                             
    
    if(status) {
        ocall_print("sgx_unseal_data status is %d\n", status);
        return status;
    } 

    //extract sk 
    sgx_ec256_private_t sk;
    memcpy(&sk, s_sk_unsealed + SECRET_KEY_SIZE_BYTES, sizeof(sgx_ec256_private_t));

    //TODO - verify that pk matches sk
    
    //Decrypt c using sk to get a symmetric encryption key k

    //Initialize the ec256 context
    sgx_ecc_state_handle_t handle;
    status = sgx_ecc256_open_context(&handle);
    
    if(status){
        ocall_print("sgx_ecc256_open_context status is %d\n", status);
        return status;
    } 
   
    //Compute the shared key with with c was encrypted
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(&sk,p_bb_pk,&shared_key, handle);
    
    
    if(status) {
        ocall_print("sgx_ecc256_compute_shared_dhkey status is %d\n", status);
        return status;
    } 

    status = encrypt(s_sk_unsealed, SECRET_KEY_SIZE_BYTES, s_encrypted, (uint8_t*)&shared_key);
    
    if(status) {
        ocall_print("encrypt status is %d\n", status);
        return status;
    } 

    return SGX_SUCCESS;
}

sgx_status_t derive_smk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                        sgx_ec_key_128bit_t* p_smk, size_t smk_size) {

   return _derive_smk(p_pk, pk_size, p_smk,smk_size, &skg_priv_key);

}

sgx_status_t verify_peer(unsigned char* reportBody, size_t reportBody_size, 
                          unsigned char* chain, size_t chain_size, 
                          unsigned char* signature, size_t signature_size,
                          sgx_ec256_public_t* peer_pk, sgx_ec256_public_t* unusable_pk, size_t pk_size)
{
    return _verify_peer(reportBody, reportBody_size, chain, chain_size, signature, signature_size, peer_pk, unusable_pk, pk_size);
}