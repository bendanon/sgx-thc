#include "common_enclave.h"

#ifdef SUPPLIED_KEY_DERIVATION

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

#endif //SUPPLIED_KEY_DERIVATION


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
    ret = sgx_ra_init_ex(&Settings::sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&Settings::sp_pub_key, b_pse, p_context);
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

sgx_status_t encrypt_key(uint8_t plaintext[SECRET_KEY_SIZE_BYTES], 
                         uint8_t ciphertext[SECRET_KEY_ENCRYPTED_SIZE_BYTES],
                         uint8_t key[SGX_AESGCM_KEY_SIZE]){

    sgx_status_t status;
    uint8_t* iv = ciphertext + SECRET_KEY_SIZE_BYTES;
    sgx_aes_gcm_128bit_tag_t* p_mac = (sgx_aes_gcm_128bit_tag_t*)(ciphertext + SECRET_KEY_SIZE_BYTES + NIST_RECOMMANDED_IV_SIZE_BYTES);

    status = sgx_read_rand((unsigned char*)iv, NIST_RECOMMANDED_IV_SIZE_BYTES);        
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
    if(status) return status;

    return SGX_SUCCESS;
}


sgx_status_t _derive_smk(sgx_ec256_public_t* p_pk, 
                         size_t pk_size, 
                         sgx_ec_key_128bit_t* p_smk, 
                         size_t smk_size, 
                         sgx_ec256_private_t* p_priv) {

    sgx_status_t status;
    sgx_ecc_state_handle_t handle;
    status = sgx_ecc256_open_context(&handle);
    if(status) return status;
   
    //Compute the shared key with with c was encrypted
    sgx_ec256_dh_shared_t shared_key;
    status = sgx_ecc256_compute_shared_dhkey(p_priv, p_pk, &shared_key, handle);
    if(status) return status;

    sgx_ec_key_128bit_t sk;
    bool derive_ret = derive_key(&shared_key, DERIVE_KEY_SMK_SK, p_smk, &sk);
                                 
    if (!derive_ret) {
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}