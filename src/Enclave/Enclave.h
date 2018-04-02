#ifndef ENCLAVE_H
#define ENCLAVE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "LogBase.h"
#include "UtilityFunctions.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

typedef enum _eEnclaveType{
    ENCLAVE_TYPE_NONE,
    ENCLAVE_TYPE_BB,
    ENCLAVE_TYPE_SKG
} eEnclaveType;

class Enclave {

public:
    Enclave(eEnclaveType type, 
                 const char *enclave_path,
                 sgx_ecall_get_ga_trusted_t sgx_ra_get_ga,
                 sgx_ecall_proc_msg2_trusted_t sgx_ra_proc_msg2_trusted,
                 sgx_ecall_get_msg3_trusted_t sgx_ra_get_msg3_trusted) : m_enclaveCreated(false), 
                                                                         m_raInitialized(false), 
                                                                         m_type(type),
                                                                         m_enclave_path(enclave_path),
                                                                         m_sgx_ra_get_ga(sgx_ra_get_ga),
                                                                         m_sgx_ra_proc_msg2_trusted(sgx_ra_proc_msg2_trusted),
                                                                         m_sgx_ra_get_msg3_trusted(sgx_ra_get_msg3_trusted) { }
    
    //static Enclave* getInstance(eEnclaveType type);
    virtual ~Enclave() { }
    sgx_status_t createEnclave();
    virtual sgx_status_t initRa() = 0;
    virtual sgx_status_t closeRa() = 0;
    sgx_enclave_id_t getID();
    sgx_status_t getStatus();
    sgx_ra_context_t getContext();
    virtual sgx_status_t VerifyPeer(unsigned char* reportBody, size_t reportBody_size, 
                             unsigned char* chain, size_t chain_size, 
                             unsigned char* signature, size_t signature_size,
                             sgx_ec256_public_t* peer_pk, sgx_ec256_public_t* unusable_pk, size_t pk_size) = 0;

    virtual sgx_status_t deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                           sgx_ec_key_128bit_t* p_smk, size_t smk_size) = 0;

    sgx_ecall_get_ga_trusted_t get_sgx_ra_get_ga() { return m_sgx_ra_get_ga; }
    sgx_ecall_proc_msg2_trusted_t get_sgx_ra_proc_msg2_trusted() { return m_sgx_ra_proc_msg2_trusted; }
    sgx_ecall_get_msg3_trusted_t get_sgx_ra_get_msg3_trusted() { return m_sgx_ra_get_msg3_trusted; }


protected:    
    //static Enclave *instance;
    //static eEnclaveType m_type;
    eEnclaveType m_type; //TODO - remove this
    const char *m_enclave_path = NULL;
    sgx_enclave_id_t enclave_id;
    sgx_status_t status;
    sgx_ra_context_t context;
    bool m_raInitialized;
    bool m_enclaveCreated;
    sgx_ecall_get_ga_trusted_t m_sgx_ra_get_ga = NULL;
    sgx_ecall_proc_msg2_trusted_t m_sgx_ra_proc_msg2_trusted = NULL;
    sgx_ecall_get_msg3_trusted_t m_sgx_ra_get_msg3_trusted = NULL;
};

#endif





