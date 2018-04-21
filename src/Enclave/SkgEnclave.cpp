#include "SkgEnclave.h"

#include <iostream>

using namespace util;
using namespace std;

/*
SkgEnclave* SkgEnclave::instance = NULL;

SkgEnclave* SkgEnclave::getInstance() {
    if (instance == NULL) {
        instance = new SkgEnclave();
    }

    return instance;
}*/


SkgEnclave::~SkgEnclave() {
    closeRa();
    sgx_destroy_enclave(enclave_id);
}


sgx_status_t SkgEnclave::initRa() {
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

sgx_status_t SkgEnclave::closeRa(){
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

sgx_status_t SkgEnclave::skgInit(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
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

sgx_status_t SkgEnclave::skgExec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, size_t pk_size,
                                 verification_report_t* p_report, size_t report_size,
                                 sgx_sealed_data_t* p_sealed_s_sk, 
                                 size_t sealed_size, uint8_t* s_encrypted, 
                                 size_t s_encrypted_size) {

    skg_exec(this->enclave_id,
             &this->status, 
             p_bb_pk, p_skg_pk, pk_size,
             p_report, report_size,
             p_sealed_s_sk, sealed_size,
             s_encrypted, s_encrypted_size);

    Log("skg_exec retval is %d", this->status);

    return this->status;
}

sgx_status_t SkgEnclave::deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
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










