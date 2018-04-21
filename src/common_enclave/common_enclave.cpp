#include "common_enclave.h"

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/signature.h>

#include <string>
#include "Base64_enclave.h"

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

sgx_status_t encrypt(uint8_t* plaintext, size_t plaintext_size,  
                         uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE]){

    sgx_status_t status;
    uint8_t* iv = ciphertext + plaintext_size;
    sgx_aes_gcm_128bit_tag_t* p_mac = (sgx_aes_gcm_128bit_tag_t*)(ciphertext + plaintext_size + NIST_RECOMMANDED_IV_SIZE_BYTES);

    status = sgx_read_rand((unsigned char*)iv, NIST_RECOMMANDED_IV_SIZE_BYTES);        
    if(status) return status;

    status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)key, 
                                        plaintext,
                                        plaintext_size,
                                        ciphertext,
                                        iv,
                                        NIST_RECOMMANDED_IV_SIZE_BYTES,
                                        NULL,
                                        0,
                                        p_mac);
    
    if(status) return status;
    
    return SGX_SUCCESS;
}

sgx_status_t decrypt(uint8_t* plaintext, size_t plaintext_size,
                     uint8_t* ciphertext, uint8_t key[SGX_AESGCM_KEY_SIZE])
{
    sgx_status_t status;

    uint8_t* iv = ciphertext + plaintext_size;
    sgx_aes_gcm_128bit_tag_t* p_mac = (sgx_aes_gcm_128bit_tag_t*)(ciphertext + plaintext_size + NIST_RECOMMANDED_IV_SIZE_BYTES);
    //Decrypt c
    status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)key,
                                        ciphertext, 
                                        plaintext_size,
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

const char* caCertBuf = "-----BEGIN CERTIFICATE-----\n"
                        "MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
                        "BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\n"
                        "BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\n"
                        "YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\n"
                        "MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\n"
                        "U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\n"
                        "DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\n"
                        "CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\n"
                        "LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\n"
                        "rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\n"
                        "L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\n"
                        "NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\n"
                        "byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\n"
                        "afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n"
                        "6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\n"
                        "RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\n"
                        "MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\n"
                        "L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\n"
                        "BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\n"
                        "NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\n"
                        "hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\n"
                        "IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\n"
                        "sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\n"
                        "zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\n"
                        "Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n"
                        "152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n"
                        "3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\n"
                        "DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\n"
                        "DaVzWh5aiEx+idkSGMnX\n"
                        "-----END CERTIFICATE-----";

std::string extract_quote_body(const char* report_buf){
    char *tok = strstr(const_cast<char*>(report_buf), "isvEnclaveQuoteBody");
    int counter = 0;
    while ((tok = strtok(tok, "\"")) != NULL)
    {
        if(2 == counter) {
            std::string quoteBody(tok);
            return quoteBody;
        }        
        tok = NULL;
        counter++;
    }
    return "";
}

bool verify_public_key(sgx_ec256_public_t* p_gb, sgx_ec256_public_t* p_ga, sgx_quote_t* p_quote_body){


    sgx_report_data_t report_data = {0};
    sgx_sha_state_handle_t sha_handle = NULL;

    // Verify the report_data in the Quote matches the expected value.
    // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
    // The second 32 bytes of report_data are set to zero.
    sgx_status_t ret = sgx_sha256_init(&sha_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print("Error, init hash failed %d", 0);
        return false;
    }

    ret = sgx_sha256_update((uint8_t *)p_ga, sizeof(sgx_ec256_public_t), sha_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print("Error, udpate hash failed %d", 0);
        return false;
    }

    ret = sgx_sha256_update((uint8_t *)p_gb, sizeof(sgx_ec256_public_t), sha_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print("Error, udpate hash failed %d", 0);
        return false;
    }

    ret = sgx_sha256_update(Settings::const_vk, sizeof(Settings::const_vk), sha_handle);
    if (ret != SGX_SUCCESS) {
        ocall_print("Error, udpate hash failed %d", 0);
        return false;
    }

    ret = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
    if (ret != SGX_SUCCESS) {
        ocall_print("Error, Get hash failed %d", 0);
        return false;
    }

    if (memcmp((uint8_t *)&report_data, (uint8_t *)&(p_quote_body->report_body.report_data), sizeof(report_data))) {
        ocall_print("Error, verify hash failed %d", 0);
        return false;
    }

    return true;
}

sgx_status_t verify_peer(verification_report_t* p_report, sgx_ec256_public_t* peer_pk){

    int ret;
    WOLFSSL_CERT_MANAGER* cm = 0;
    byte  derCert[MAX_CERT_SIZE];
    RsaKey pubKey;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pubKeyTmp;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        ocall_print("wolfSSL_CertManagerNew() failed %d\n", 0);
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CertManagerLoadCABuffer(cm, (unsigned char*)caCertBuf, strlen(caCertBuf) ,WOLFSSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        ocall_print("wolfSSL_CertManagerLoadCA() failed (%d)\n", ret);

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wolfSSL_CertManagerVerifyBuffer(cm, p_report->cert_chain, p_report->cert_chain_size, WOLFSSL_FILETYPE_PEM);
    ocall_print("chain_size %d", p_report->cert_chain_size);

    if (ret != SSL_SUCCESS) {

        ocall_print("wolfSSL_CertManagerVerify() failed (%d)\n", ret);

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    /*By now we know the certificate chain is valid against the hard-coded CA certificate*/

    int derCertSz = wolfSSL_CertPemToDer(p_report->cert_chain, p_report->cert_chain_size, derCert, MAX_CERT_SIZE, CERT_TYPE);

    if(derCertSz <= 0){
        ocall_print("wolfSSL_CertPemToDer failed %d", derCertSz);

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    /* convert cert from DER to internal WOLFSSL_X509 struct */
    cert = wolfSSL_X509_d2i(&cert, derCert, derCertSz);
    if (cert == NULL){
        ocall_print("Failed to convert DER to WOLFSSL_X509 %d", 0);

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    /* extract PUBLIC KEY from cert */
    pubKeyTmp = wolfSSL_X509_get_pubkey(cert);
    if (pubKeyTmp == NULL) {
        ocall_print("wolfSSL_X509_get_pubkey failed %d", 0);
        
        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }
        

    if(0 != wc_InitRsaKey(&pubKey, 0)){
        ocall_print("wc_InitRsaKey failed %d", 0);      

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    word32 idx = 0;
    ret = wc_RsaPublicKeyDecode((byte*)pubKeyTmp->pkey.ptr, &idx, &pubKey,
                                pubKeyTmp->pkey_sz);
    if (ret != 0){
        ocall_print("wc_RsaPublicKeyDecode failed, %d", ret);

        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC, 
                            p_report->response_body, p_report->response_body_size, 
                            p_report->signature, RA_SIGNATURE_SIZE_BYTES, 
                            &pubKey, sizeof(pubKey));

    
    if(0 != ret){
        ocall_print("Signature Verification failed, %d", ret);
        wolfSSL_CertManagerFree(cm);
        return SGX_ERROR_UNEXPECTED;
    }

    wolfSSL_CertManagerFree(cm);

    /*By now we know the report is valid*/
    sgx_quote_t quote_body;
    string isvEnclaveQuoteBody = extract_quote_body((char*)p_report->response_body);
    memcpy(&quote_body, base64_decode(isvEnclaveQuoteBody).c_str(), sizeof(quote_body));
    

    if(0!=memcmp(Settings::mrsigner, 
                 base64_encode((uint8_t*)&quote_body.report_body.mr_signer, sizeof(quote_body.report_body.mr_signer)).c_str(),
                 strlen(Settings::mrsigner)))
    {
        ocall_print("mrsigner is invealid %d", 0);
        return SGX_ERROR_UNEXPECTED;
    }

    //TODO - MRENCLAVE Base64encodeUint8((uint8_t*)&m_quote_body.report_body.mr_enclave, sizeof(m_quote_body.report_body.mr_enclave)

    if(!verify_public_key(peer_pk, (sgx_ec256_public_t*)p_report->unusable_pk, &quote_body)){
        ocall_print("verify public key failed %d", 0);
        return SGX_ERROR_UNEXPECTED;
    }
    
    wolfSSL_EVP_PKEY_free(pubKeyTmp);
    wolfSSL_X509_free(cert);

    return SGX_SUCCESS;    
}