#ifndef BB_ENCLAVE_H
#define BB_ENCLAVE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "LogBase.h"
#include "UtilityFunctions.h"
#include "bb_enclave_u.h"
#include "Enclave.h"
#include "../GeneralSettings.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

class BbEnclave : public Enclave {

public:
    //friend class Enclave;
    BbEnclave() : Enclave(ENCLAVE_TYPE_BB, 
                          Settings::bb_enclave_path,
                          sgx_ra_get_ga, 
                          sgx_ra_proc_msg2_trusted, 
                          sgx_ra_get_msg3_trusted) { }
    virtual ~BbEnclave();
    virtual sgx_status_t initRa();
    virtual sgx_status_t closeRa();

    sgx_status_t bbInit1(sgx_sealed_data_t* sealed_data, size_t sealed_size, 
                         sgx_ec256_public_t* bb_pk, sgx_ec256_public_t* skg_pk, 
                         size_t pk_size, uint32_t local_id, uint32_t* neighbor_ids, size_t neighbor_ids_size,
                         uint32_t vertices_num);

    
    sgx_status_t bbInit2(sgx_sealed_data_t* p_sealed_k, uint8_t* s_encrypted, 
                         size_t s_encrypted_size, sgx_sealed_data_t* p_sealed_s, 
                         size_t sealed_size);

    sgx_status_t bbExec(sgx_sealed_data_t* p_sealed_s, size_t sealed_size, 
                        uint8_t* B_in, size_t B_in_size, uint8_t* B_out, 
                        size_t B_out_size);

    virtual sgx_status_t deriveSmk(sgx_ec256_public_t* p_pk, size_t pk_size, 
                                   sgx_ec_key_128bit_t* p_smk, size_t smk_size);
};

#endif





