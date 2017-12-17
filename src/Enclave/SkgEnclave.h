#ifndef SKG_ENCLAVE_H
#define SKG_ENCLAVE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "LogBase.h"
#include "UtilityFunctions.h"
#include "skg_enclave_u.h"
#include "Enclave.h"
#include "../GeneralSettings.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

class SkgEnclave : public Enclave {

public:
    //friend class Enclave;
    SkgEnclave() : Enclave(ENCLAVE_TYPE_SKG, 
                           Settings::skg_enclave_path,
                           sgx_ra_get_ga, 
                           sgx_ra_proc_msg2_trusted, 
                           sgx_ra_get_msg3_trusted) { }

    virtual ~SkgEnclave();
    virtual sgx_status_t initRa();
    virtual sgx_status_t closeRa();
    
    sgx_status_t skgInit(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                         sgx_ec256_public_t* pk, size_t pk_size);

    sgx_status_t skgExec(sgx_ec256_public_t* p_bb_pk, sgx_ec256_public_t* p_skg_pk, 
                         size_t pk_size, sgx_sealed_data_t* p_sealed_s_sk, 
                         size_t sealed_size, uint8_t* s_encrypted, 
                         size_t s_encrypted_size);

    virtual sgx_status_t deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size,
                                   sgx_ec_key_128bit_t* p_smk, size_t smk_size);

};

#endif





