#include <stdarg.h>
#include <stdio.h>

#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "../GeneralSettings.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};


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

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key) {
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++) {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    /*vk - The default implementation means this is a derivative of the shared secret gab. 
    For our use, this is not good since we plan on the verification report to be 
    publicly verifiable, hence need vk to be public. So we set it to be zeroes.*/
    if(key_id == DERIVE_KEY_MK_VK)
        memcpy(second_derived_key, Settings::const_vk, sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}


sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id,
                            sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key) {
    bool derive_ret = false;

    if (NULL == shared_key) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
                            smk_key, sk_key);
    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
                            mk_key, vk_key);


    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context) {
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse) {
        int busy_retry_times = 2;
        do {
            ret = sgx_create_pse_session();
        } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse) {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context) {
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size) {
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t)) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret) {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret) {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    } while(0);

    return ret;
}


sgx_status_t verify_secret_data (
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    uint32_t max_verification_length,
    uint8_t *p_ret) {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        uint8_t *decrypted = (uint8_t*) malloc(sizeof(uint8_t) * secret_size);
        uint8_t aes_gcm_iv[12] = {0};

        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         decrypted,
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *) (p_gcm_mac));

        if (SGX_SUCCESS == ret) {
            if (decrypted[0] == 0) {
                if (decrypted[1] != 1) {
                    ret = SGX_ERROR_INVALID_SIGNATURE;
                }
            } else {
                ret = SGX_ERROR_UNEXPECTED;
            }
        }

    } while(0);

    return ret;
}


/******************************************THC**********************************/


#include "BlackBoxExecuter.h"
#include "../../thc/App/th_definitions.h"


/*SKG enclave internal data*/
uint8_t s_sk[SKG_DATA_SIZE_BYTES];

/*BB enclave internal data*/
uint8_t k[SECRET_KEY_SIZE_BYTES];
BlackBoxExecuter bbx;

void ocall_print(const char* format, uint32_t number){
    char output[50];
    memset(output,0,50);
    snprintf(output, 50, format, number);
    ocall_print(output);
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
[Initialization: no input] - *SKG ENCLAVE CODE*
1. Use SGX hardware randomness to generate shared secret key s
2. Generate an encryption key pair (pk,sk), output pk.
3. Use the "independent attestation" mechanism to generate an Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode". This is Q’, output.
4. Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data. output.
***/
sgx_status_t skg_init(sgx_sealed_data_t* p_sealed_data, size_t sealed_size, 
                      sgx_ec256_public_t* p_pk,size_t pk_size) {
    
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

        //Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data.        
        status = sgx_seal_data(0, NULL, sizeof(s_sk), s_sk, sealed_size, p_sealed_data);
        ocall_print("sgx_seal_data status is %d\n", status);
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
                       sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size) {

    
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
