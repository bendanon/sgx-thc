#include "Enclave_t.h"
#include "sgx_uae_service.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <string.h>
#include <stdio.h>
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include <assert.h>
#include "../App/th_definitions.h"
#include "BlackBoxExecuter.h"

static const sgx_ec256_public_t skg_const_pub_key = { { 
    0xC4, 0x89, 0x77, 0x40, 0x59, 0x0B, 0x2D, 0xEC,     
    0x3B, 0x28, 0xF5, 0x97, 0x95, 0x01, 0x7D, 0xB8,     
    0x33, 0x63, 0xC9, 0x0B, 0xEF, 0xBF, 0x2F, 0xC8,     
    0xC9, 0xA0, 0x89, 0x0C, 0xE3, 0x97, 0xD8, 0x0A }
    , {    
    0xE4, 0xA0, 0x8D, 0x4C, 0xBA, 0x24, 0x83, 0x33,     
    0x2A, 0xD2, 0x5C, 0x30, 0x09, 0x6C, 0xE8, 0x10,     
    0x7C, 0x6C, 0x13, 0x32, 0xB9, 0x2A, 0xE5, 0x38,     
    0x3D, 0x9F, 0xA6, 0x27, 0xA4, 0x13, 0xBA, 0x98 }
};
    
static const sgx_ec256_private_t skg_const_priv_key = {    
    0x4B, 0x25, 0x58, 0xD3, 0xBB, 0xAF, 0x27, 0x4E,    
    0xA0, 0x51, 0x78, 0xC4, 0x7D, 0x30, 0xEF, 0xFE,    
    0x92, 0x37, 0x4F, 0x47, 0x27, 0x84, 0x86, 0xD6,    
    0xAB, 0xC4, 0xE9, 0x20, 0x66, 0x14, 0x72, 0xE0     
};

static const sgx_ec256_public_t bb_const_pub_key = { {    
    0x87, 0xD8, 0x58, 0x0D, 0x66, 0x38, 0xF4, 0x0A, 
    0x5F, 0xE5, 0x16, 0x95, 0x25, 0xEE, 0x70, 0xA8, 
    0xAC, 0xA1, 0x67, 0xBA, 0xA4, 0x70, 0x6B, 0x3D, 
    0x09, 0xD0, 0x26, 0x1D, 0x50, 0x00, 0xA0, 0xAA }
    , {    
    0x28, 0x84, 0xDE, 0xD1, 0x20, 0x72, 0x8C, 0x7D, 
    0x62, 0x4C, 0xA5, 0x7B, 0xE9, 0x1B, 0xF2, 0xB5, 
    0xA0, 0x91, 0x1B, 0xDC, 0xF3, 0x56, 0x4A, 0xC1, 
    0x2A, 0x4B, 0x33, 0x71, 0x4F, 0x71, 0x8B, 0xA8 } 
};
    
static const sgx_ec256_private_t bb_const_priv_key = {    
    0xA2, 0x46, 0x87, 0xC0, 0x8A, 0x41, 0xAB, 0xB9, 
    0x07, 0x3A, 0xEE, 0x9C, 0x4A, 0x68, 0x14, 0x63, 
    0xB3, 0xB2, 0x1E, 0x08, 0x58, 0x51, 0x27, 0xA9, 
    0xFF, 0x97, 0x0C, 0x1F, 0xB3, 0xD1, 0x67, 0xE0    
};


void ocall_print(const char* format, uint32_t number){
    char output[50];
    memset(output,0,50);
    snprintf(output, 50, format, number);
    ocall_print(output);
}

/*SKG enclave internal data*/
uint8_t s_sk[SKG_DATA_SIZE_BYTES];

/*BB enclave internal data*/
uint8_t k[SECRET_KEY_SIZE_BYTES];
BlackBoxExecuter bbx;

/***
[Initialization: no input] - *SKG ENCLAVE CODE*
1. Use SGX hardware randomness to generate shared secret key s
2. Generate an encryption key pair (pk,sk), output pk.
3. Use the "independent attestation" mechanism to generate an Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode". This is Q’, output.
4. Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data. output.
***/
sgx_status_t skg_init(sgx_sealed_data_t* p_sealed_data, size_t sealed_size, 
                      sgx_ec256_public_t* p_pk,size_t pk_size,
                      sgx_target_info_t* p_target_info,
                      sgx_report_t* p_report) {
    
        memset(s_sk, 0, sizeof(s_sk));        
        sgx_status_t status;

        //Use SGX hardware randomness to generate shared secret key s
        status = sgx_read_rand((unsigned char*)s_sk, SECRET_KEY_SIZE_BYTES);        
        ocall_print("sgx_read_rand status is %d\n", status);
        if(status) return status;
        
        //Generate an encryption key pair (pk,sk), output pk
        sgx_ecc_state_handle_t handle;
        sgx_ec256_private_t sk;
    
        status = sgx_ecc256_open_context(&handle);
        ocall_print("sgx_ecc256_open_context status is %d\n", status);
        if(status) return status;
        
        status = sgx_ecc256_create_key_pair(&sk, p_pk, handle);

        ocall_print("sgx_ecc256_create_key_pair status is %d\n", status);
        if(status) return status;        
        memcpy(s_sk + SECRET_KEY_SIZE_BYTES, &sk, sizeof(sgx_ec256_private_t));


        //Create the report for the skg pk attestation quote (Q')
        sgx_report_data_t report_data;
        memset(&report_data, 0, sizeof(report_data));
        memcpy(&report_data, p_pk, sizeof(sgx_ec256_public_t));
                
        status = sgx_create_report(p_target_info, NULL, p_report);
        ocall_print("sgx_create_report status is %d\n", status);
        if(status) return status;

        //Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data.        
        status = sgx_seal_data(0, NULL, sizeof(s_sk), s_sk, sealed_size, p_sealed_data);
        ocall_print("sgx_seal_data status is %d\n", status);
        if(status) return status;

        return SGX_SUCCESS;
    }




sgx_status_t encrypt_key(uint8_t plaintext[SECRET_KEY_SIZE_BYTES], 
                         uint8_t ciphertext[SECRET_KEY_ENCRYPTED_SIZE_BYTES],
                         uint8_t key[SGX_AESGCM_KEY_SIZE]){

    sgx_status_t status;
    uint8_t* iv = ciphertext + SECRET_KEY_SIZE_BYTES;
    sgx_aes_gcm_128bit_tag_t* p_mac = (sgx_aes_gcm_128bit_tag_t*)(ciphertext + SECRET_KEY_SIZE_BYTES + NIST_RECOMMANDED_IV_SIZE_BYTES);

    status = sgx_read_rand((unsigned char*)iv, NIST_RECOMMANDED_IV_SIZE_BYTES);        
    ocall_print("sgx_read_rand for iv status is %d\n", status);
    if(status) return status;

    status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)key, 
                                        plaintext,
                                        SECRET_KEY_SIZE_BYTES,
                                        ciphertext,
                                        iv,
                                        NIST_RECOMMANDED_IV_SIZE_BYTES,
                                        NULL,
                                        0,
                                        p_mac);
    
    ocall_print("sgx_rijndael128GCM_encrypt status is %d\n", status);
    if(status) return status;
    
    return SGX_SUCCESS;
}

sgx_status_t decrypt_key(uint8_t plaintext[SECRET_KEY_SIZE_BYTES], 
                         uint8_t ciphertext[SECRET_KEY_ENCRYPTED_SIZE_BYTES],
                         uint8_t key[SGX_AESGCM_KEY_SIZE])
{
    sgx_status_t status;

    uint8_t* iv = ciphertext + SECRET_KEY_SIZE_BYTES;
    sgx_aes_gcm_128bit_tag_t* p_mac = (sgx_aes_gcm_128bit_tag_t*)(ciphertext + SECRET_KEY_SIZE_BYTES + NIST_RECOMMANDED_IV_SIZE_BYTES);
    //Decrypt c
    status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)key,
                                        ciphertext, 
                                        SECRET_KEY_SIZE_BYTES,
                                        plaintext,
                                        iv,
                                        NIST_RECOMMANDED_IV_SIZE_BYTES,
                                        NULL,
                                        0,
                                        p_mac);
    
    ocall_print("sgx_rijndael128GCM_decrypt status is %d\n", status);
    if(status) return status;

    return SGX_SUCCESS;
}


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
                       sgx_target_info_t* p_target_info,
                       sgx_report_t* p_report) {

    
    memset(k, 0, sizeof(k));
    sgx_status_t status;
    
    //Compute k=DH(bbsk, pk) the shared DH key of skg and bb
    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t sk;

    status = sgx_ecc256_open_context(&handle);
    ocall_print("sgx_ecc256_open_context status is %d\n", status);
    if(status) return status;
    
    status = sgx_ecc256_create_key_pair(&sk, p_bb_pk, handle);
    ocall_print("sgx_ecc256_create_key_pair status is %d\n", status);
    if(status) return status;
    
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(&sk,p_skg_pk,&shared_key, handle);
    ocall_print("sgx_ecc256_compute_shared_dhkey status is %d\n", status);
    if(status) return status;

    //shared_key is k
    memcpy(k ,&shared_key, SECRET_KEY_SIZE_BYTES);

    //Create the report for the bb attestation quote (Q) containing bbpk
    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    assert(sizeof(sgx_report_data_t) >= sizeof(sgx_ec256_public_t));
    memcpy(&report_data, p_bb_pk, sizeof(sgx_ec256_public_t));
            
    status = sgx_create_report(p_target_info, NULL, p_report);
    ocall_print("sgx_create_report status is %d\n", status);
    if(status) return status;

    //Seal (k) [sealing to MRENCLAVE]
    status = sgx_seal_data(0, NULL, sizeof(k), k, sealed_size, p_sealed_data);
    ocall_print("sgx_seal_data status is %d\n", status);
    if(status) return status;

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

    sgx_status_t status;
    
    //Unseal s,sk
    uint8_t s_sk_unsealed[SKG_DATA_SIZE_BYTES];
    uint32_t unsealed_text_length = SKG_DATA_SIZE_BYTES;

    status = sgx_unseal_data(p_sealed_s_sk,
                             NULL,
                             0,
                             s_sk_unsealed, 
                             &unsealed_text_length);
                             
    ocall_print("sgx_unseal_data status is %d\n", status);
    if(status) return status;

    //TODO-remove
    ocall_print("s_sk=s_sk_decrypted? %d\n", memcmp(s_sk_unsealed, s_sk, SKG_DATA_SIZE_BYTES));

    //extract sk 
    sgx_ec256_private_t sk;
    memcpy(&sk, s_sk_unsealed + SECRET_KEY_SIZE_BYTES, sizeof(sgx_ec256_private_t));

    //TODO - verify that pk matches sk
    
    //Decrypt c using sk to get a symmetric encryption key k

    //Initialize the ec256 context
    sgx_ecc_state_handle_t handle;
    status = sgx_ecc256_open_context(&handle);
    ocall_print("sgx_ecc256_open_context status is %d\n", status);
    if(status) return status;
   
    //Compute the shared key with with c was encrypted
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(&sk,p_bb_pk,&shared_key, handle);
    ocall_print("sgx_ecc256_compute_shared_dhkey status is %d\n", status);
    if(status) return status;    
    
    //TODO-remove
    ocall_print("k=shared_key? %d\n", memcmp(&shared_key, k, SECRET_KEY_SIZE_BYTES));

    status = encrypt_key(s_sk_unsealed, s_encrypted, (uint8_t*)&shared_key);
    ocall_print("encrypt_key status is %d\n", status);
    if(status) return status;

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
    sgx_status_t status;

    //Unseal k
    uint8_t k_unsealed[SECRET_KEY_SIZE_BYTES];
    uint32_t unsealed_text_length = sizeof(k_unsealed);

    status = sgx_unseal_data(p_sealed_k,
                             NULL,
                             0,
                             k_unsealed, 
                             &unsealed_text_length);
                             
    ocall_print("sgx_unseal_data status is %d\n", status);
    if(status) return status;

    //TODO-remove
    ocall_print("k=k_unsealed? %d\n", memcmp(k_unsealed, k, SECRET_KEY_SIZE_BYTES));

    uint8_t s_decrypted[SECRET_KEY_SIZE_BYTES];
    memset(s_decrypted, 0, SECRET_KEY_SIZE_BYTES);

    //Decrypt c' with k to get s
    status = decrypt_key(s_decrypted, s_encrypted,k_unsealed);
    ocall_print("decrypt_key status is %d\n", status);
    if(status) return status;

    //Seal (s) [to MRENCLAVE] and output sealed data.
    status = sgx_seal_data(0, NULL, sizeof(s_decrypted), s_decrypted, sealed_size, p_sealed_s);
    ocall_print("sgx_seal_data status is %d\n", status);
    if(status) return status;

    return SGX_SUCCESS;
}



/*
[Execution: input sealed data (s), memory buffer B_in]
1. Unseal s
2. Execute B_out=X_s(B_in)
3. Output B_out
*/
sgx_status_t bb_exec(sgx_sealed_data_t* p_sealed_s,  size_t sealed_size, //in (Seal(s))
                       uint8_t* B_in, size_t B_in_size,                   //in (B_in)
                       uint8_t* B_out, size_t B_out_size)                 //out (B_out)
{
    sgx_status_t status;

    
    if(!bbx.IsInitialized())
    {
        //Unseal s
        uint8_t s_unsealed[SECRET_KEY_SIZE_BYTES];
        uint32_t unsealed_text_length = sizeof(s_unsealed);

        status = sgx_unseal_data(p_sealed_s,
                                NULL,
                                0,
                                s_unsealed, 
                                &unsealed_text_length);
                                
        ocall_print("sgx_unseal_data status is %d\n", status);
        if(status) return status;

        //TODO-remove
        ocall_print("s=s_unsealed? %d\n", memcmp(s_unsealed, s_sk, SECRET_KEY_SIZE_BYTES));

        bbx.Init(s_unsealed, SECRET_KEY_SIZE_BYTES);
    }   
    
    status = bbx.Execute(B_in, B_in_size, B_out, B_out_size);
    ocall_print("bbx.Execute status is %d\n", status);
    if(status) return status;

    return SGX_SUCCESS;
}