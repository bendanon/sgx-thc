#ifndef ENCLAVE_H
#define ENCLAVE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "LogBase.h"
#include "UtilityFunctions.h"
#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

class Enclave {

public:
    static Enclave* getInstance();
    virtual ~Enclave();
    sgx_status_t createEnclave();
    sgx_status_t initRa();
    sgx_status_t closeRa();
    sgx_enclave_id_t getID();
    sgx_status_t getStatus();
    sgx_ra_context_t getContext();

    sgx_status_t skgInit(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                         sgx_ec256_public_t* pk, size_t pk_size);

    sgx_status_t bbInit1(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                         sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, 
                         size_t pk_size);

    sgx_status_t skgExec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, 
                         size_t pk_size, sgx_sealed_data_t* p_sealed_s_sk, 
                         size_t sealed_size, uint8_t* s_encrypted, 
                         size_t s_encrypted_size);
    
    sgx_status_t bbInit2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, 
                         size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, 
                         size_t sealed_size);

    sgx_status_t bbExec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, 
                        uint8_t* B_in, size_t B_in_size, uint8_t* B_out, 
                        size_t B_out_size);

    sgx_status_t deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                           sgx_ec_key_128bit_t* p_smk, size_t smk_size);


private:
    Enclave();
    static Enclave *instance;
    const char *enclave_path = "isv_enclave.signed.so";
    sgx_enclave_id_t enclave_id;
    sgx_status_t status;
    sgx_ra_context_t context;
    bool m_raInitialized;
    bool m_enclaveCreated;
};

#endif





