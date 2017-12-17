#ifndef SkgServer_H
#define SkgServer_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

#include "sgx_urts.h"
#include <cassert>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "sgx_tseal.h"
#include <stdlib.h>
#include "sgx_utils.h"

#include "LogBase.h"
#include "../GeneralSettings.h"
#include "SkgEnclave.h"
#include "Messages.pb.h"
#include "VerificationReport.h"
#include "AttestationClient.h"
#include "Network_def.h"
#include "UtilityFunctions.h"
#include "NetworkManagerServer.h"


using namespace std;
using namespace util;

class SkgServer {

private:
    static string public_file_name;
    static string secrets_file_name;
    static string report_file_name;

public:
    SkgServer(SkgEnclave* pEnclave);
    virtual ~SkgServer();

    /***
    [Initialization: no input]
    1. Use SGX hardware randomness to generate shared secret key s
    2. Generate an encryption key pair (pk,sk), output pk.
    3. Use the "independent attestation" mechanism to generate an Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode". This is Q’, output.
    4. Seal the data (s,sk) [sealing to MRENCLAVE] and output sealed data. output.
    5. Obtain a certificate using the attestation service
    ***/
    bool init();
    
    void start();

    /*
    [Execution: input pk, sealed data (s,sk), bb-public bbpk , an attestation quote Q]
    1. Verify that Q is a valid Intel-signed quote of the form "c was generated by [X-Black-Box Enclave] running in secure mode"
    2. Unseal s,sk (verify that pk matches sk)
    3. Compute a symmetric encryption key k using pk and bbpk 
    4. Compute and output c'=E_k(s) --- the (symmetric) encryption of s under k
    */
    bool processPkRequest(Messages::PkRequest& pkRequest, 
                          Messages::CertificateMSG& certMsg);


    bool processGetSecretRequest(Messages::CertificateMSG& certMsg, 
                                 Messages::GetSecretResponse& getSecretResponse);

    //TODO - this should be private and called by NetworkManagerServer
    vector<string> incomingHandler(string v, int type);

private:
    bool readAssets();
    bool writeAssets();
    bool obtainAssets();

private:
    NetworkManagerServer *nm = NULL;
    VerificationReport m_report;
    SkgEnclave* m_pEnclave;
    AttestationClient* m_pClient;
    sgx_ec256_public_t* p_skg_pk = NULL;
    sgx_sealed_data_t* p_sealed_s_sk = NULL;
};

#endif










