#include "Enclave.h"
//#include "BbEnclave.h"
//#include "SkgEnclave.h"
#include <iostream>

using namespace util;
using namespace std;

//Enclave* Enclave::instance = NULL;
//eEnclaveType Enclave::m_type = ENCLAVE_TYPE_NONE;

/*
Enclave* Enclave::getInstance(eEnclaveType type) {
    if (instance == NULL) {
        m_type = type;
        if(m_type == ENCLAVE_TYPE_BB) {
            this->m_enclave_path = Settings::bb_m_enclave_path;
            instance = new BbEnclave();
        } else if(m_type == ENCLAVE_TYPE_SKG) {
            this->m_enclave_path = Settings::skg_m_enclave_path; 
            instance = new SkgEnclave();
        }
        
    }

    return instance;
}
*/

sgx_status_t Enclave::createEnclave() {
    sgx_status_t ret;
    int launch_token_update = 0;
    int enclave_lost_retry_time = 1;
    sgx_launch_token_t launch_token = {0};

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

    do {
        ret = sgx_create_enclave(this->m_enclave_path,
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
    if(!m_enclaveCreated){
        Log("Enclave::getID - enclave not created");
        return 0;
    }
    return this->enclave_id;
}

sgx_status_t Enclave::getStatus() {
    return this->status;
}

sgx_ra_context_t Enclave::getContext() {
    if(!m_enclaveCreated || !m_raInitialized){
        Log("Enclave::getContext - !m_enclaveCreated || !m_raInitialized");
    }
    return this->context;
}






