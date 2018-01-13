#include "BbEnclave.h"

#include <iostream>

using namespace util;
using namespace std;

/*
BbEnclave* BbEnclave::instance = NULL;

BbEnclave* BbEnclave::getInstance() {
    if (instance == NULL) {
        instance = new BbEnclave();
    }

    return instance;
}
*/

BbEnclave::~BbEnclave() {
    closeRa();
    sgx_destroy_enclave(enclave_id);
}


sgx_status_t BbEnclave::initRa() {
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

sgx_status_t BbEnclave::closeRa(){
    sgx_status_t ret;

    if(!m_enclaveCreated)
    {
        Log("Called closeRa but enclave not created", log::error);
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    if(!m_raInitialized)
    {
        Log("Called closeRa but ra not initialized");
        return SGX_SUCCESS;
    }

    if(context == INT_MAX)
    {
        Log("Called closeRa but INT_MAX == context, enclave_ra_close NOT called", log::error);
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


sgx_status_t BbEnclave::bbInit1(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                              sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, 
                              size_t pk_size, uint32_t local_id, uint32_t* neighbor_ids, size_t neighbor_ids_size,
                              uint32_t vertices_num) {

    bb_init_1(this->enclave_id,
             &this->status, 
             sealed_data, 
             sealed_size, 
             bb_pk,
             skg_pk, 
             pk_size,
             local_id,
             neighbor_ids,
             neighbor_ids_size,
             vertices_num);

    if(SGX_SUCCESS != this->status) {
        Log("bb_init_1 failed, retval is %d", this->status, log::error);
    }
    

    return this->status;
}


sgx_status_t BbEnclave::bbInit2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, 
                              size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, 
                              size_t sealed_size) {
                                  
    bb_init_2(this->enclave_id,
             &this->status, 
             p_sealed_k, 
             s_encrypted, 
             s_encrypted_size, 
             p_sealed_s,
             sealed_size);

    if(SGX_SUCCESS != this->status) {
        Log("bb_init_2 failed, retval is %d", this->status, log::error);
    }

    return this->status;
}

sgx_status_t BbEnclave::bbExec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, 
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

    if(SGX_SUCCESS != this->status) {
        Log("bb_exec failed, retval is %d", this->status, log::error);
    }

    return this->status;
}


sgx_status_t BbEnclave::deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                                sgx_ec_key_128bit_t* p_smk, size_t smk_size){
    
    derive_smk(this->enclave_id,
               &this->status,
               p_pk,
               pk_size,
               p_smk,
               smk_size);
    
    if(SGX_SUCCESS != this->status) {
        Log("derive_smk failed, retval is %d", this->status, log::error);
    }

    return this->status;
}











