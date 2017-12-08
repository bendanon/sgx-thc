#include "Enclave.h"

#include <iostream>

using namespace util;
using namespace std;

Enclave* Enclave::instance = NULL;

Enclave::Enclave() : m_enclaveCreated(false), m_raInitialized(false) {}

Enclave* Enclave::getInstance() {
    if (instance == NULL) {
        instance = new Enclave();
    }

    return instance;
}


Enclave::~Enclave() {
    closeRa();
    sgx_destroy_enclave(enclave_id);
}


sgx_status_t Enclave::initRa() {
    sgx_status_t ret;

    if(!m_enclaveCreated)
    {
        Log("Called initRa but enclave not created");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    if(m_raInitialized)
    {
        Log("Called initRa but enclave already initialized");
        return SGX_SUCCESS;
    }

    ret = enclave_init_ra(this->enclave_id,
                                  &this->status,
                                  false,
                                  &this->context);
    if(ret != SGX_SUCCESS)
    {
        Log("Call enclave_init_ra failed");
        return ret;
    }

    Log("Ra initizalized");
    m_raInitialized = true;    
    return SGX_SUCCESS;
}

sgx_status_t Enclave::closeRa(){
    sgx_status_t ret;

    if(!m_enclaveCreated)
    {
        Log("Called closeRa but enclave not created");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    if(!m_raInitialized)
    {
        Log("Called closeRa but ra not initialized");
        return SGX_SUCCESS;
    }

    if(context == INT_MAX)
    {
        Log("Called closeRa but INT_MAX == context, enclave_ra_close NOT called");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    ret = enclave_ra_close(enclave_id, &status, context);
    if (SGX_SUCCESS != ret || status) {            
        Log("Error, call enclave_ra_close fail", log::error);
        return ret;
    }

    Log("Call enclave_ra_close success");  
    m_raInitialized = false;
    return SGX_SUCCESS;
}


sgx_status_t Enclave::createEnclave() {
    sgx_status_t ret;
    int launch_token_update = 0;
    int enclave_lost_retry_time = 1;
    sgx_launch_token_t launch_token = {0};

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

    do {
        ret = sgx_create_enclave(this->enclave_path,
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 &this->enclave_id, NULL);

        if (SGX_SUCCESS != ret) {
            Log("Error, call sgx_create_enclave fail", log::error);
            print_error_message(ret);
            break;
        } else {
            Log("Call sgx_create_enclave success");            
        }

    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

    if (ret == SGX_SUCCESS)
    {
        Log("Enclave created, ID: %llx", this->enclave_id);
        m_enclaveCreated = true;
    }

    return ret;
}


sgx_enclave_id_t Enclave::getID() {
    return this->enclave_id;
}

sgx_status_t Enclave::getStatus() {
    return this->status;
}

sgx_ra_context_t Enclave::getContext() {
    return this->context;
}

sgx_status_t Enclave::skgInit(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                              sgx_ec256_public_t* pk, size_t pk_size){

    skg_init(this->enclave_id,
             &this->status, 
             sealed_data, 
             sealed_size, 
             pk, 
             pk_size);

    Log("skg_init retval is %d", this->status);

    return this->status;
}


sgx_status_t Enclave::bbInit1(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                              sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, 
                              size_t pk_size) {

    bb_init_1(this->enclave_id,
             &this->status, 
             sealed_data, 
             sealed_size, 
             bb_pk,
             skg_pk, 
             pk_size);

    Log("bb_init_1 retval is %d", this->status);

    return this->status;
}


sgx_status_t Enclave::skgExec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, 
                              size_t pk_size, sgx_sealed_data_t* p_sealed_s_sk, 
                              size_t sealed_size, uint8_t* s_encrypted, 
                              size_t s_encrypted_size) {

    skg_exec(this->enclave_id,
             &this->status, 
             p_bb_pk, 
             p_skg_pk, 
             pk_size, 
             p_sealed_s_sk,
             sealed_size,
             s_encrypted,
             s_encrypted_size);

    Log("skg_exec retval is %d", this->status);

    return this->status;
}

sgx_status_t Enclave::bbInit2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, 
                              size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, 
                              size_t sealed_size) {
                                  
    bb_init_2(this->enclave_id,
             &this->status, 
             p_sealed_k, 
             s_encrypted, 
             s_encrypted_size, 
             p_sealed_s,
             sealed_size);

    Log("bb_init_2 retval is %d", this->status);

    return this->status;
}

sgx_status_t Enclave::bbExec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, 
                             uint8_t* B_in, size_t B_in_size, uint8_t* B_out, 
                             size_t B_out_size){

    bb_exec(this->enclave_id,
             &this->status, 
             p_sealed_s, 
             sealed_size, 
             B_in, 
             B_in_size,
             B_out,
             B_out_size);

    Log("bb_exec retval is %d", this->status);

    return this->status;
}


sgx_status_t Enclave::deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                                sgx_ec_key_128bit_t* p_smk, size_t smk_size){
    
    derive_smk(this->enclave_id,
               &this->status,
               p_pk,
               pk_size,
               p_smk,
               smk_size);
    
    Log("derive_smk retval is %d", this->status);

    return this->status;
}











