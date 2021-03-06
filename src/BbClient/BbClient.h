#ifndef BbClient_H
#define BbClient_H

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
#include "BbEnclave.h"
#include "Messages.pb.h"
#include "VerificationReport.h"
#include "AttestationClient.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "UtilityFunctions.h"
#include "NetworkManagerClient.h"
#include "NetworkManagerServer.h"
#include <jsoncpp/json/json.h>

#include <boost/thread.hpp>
#include <boost/chrono.hpp>

#include "ThcServer.h"
#include "ThcClient.h"

using namespace std;
using namespace util;

class BbClient {


private:
    static string secret_file_name;

public:
    BbClient(BbEnclave* pEnclave, Json::Value& config);
    virtual ~BbClient();
        
    void obtainSecretFromSkg();
    bool runThcProtocol(uint8_t* outbuf, size_t outbuf_len);
    
    bool hasSecret();

    bool generatePkRequest(Messages::PkRequest& pkRequest);


    /***
    [Initialization-step 1: input pk, attestation quote Q']
    1. Verify that Q' is a valid Intel-signed quote that "pk was generated by [Secret-Key-Generation Enclave] running in secure mode"
    2. Generate an encryption key pair (bbpk, bbsk), output bbpk.
    3. Compute k=DH(bbsk, pk) the shared DH key of skg and bb
    4. Use the "independent attestation" mechanism to generate an Intel-signed quote that "bbpk was generated by [X-Black-Box Enclave] running in secure mode". This is Q, output.
    5. Seal (k) [sealing to MRENCLAVE] and the sealed data.
    ***/
    bool processPkResponse(Messages::CertificateMSG& skgCertMsg, 
                           Messages::CertificateMSG& bbCertMsg);


    /***
    [Initialization-step 2: input sealed data (k), ciphertext c']
    1. Unseal k
    2. Decrypt c' with k to get s
    3. Seal (s) [to MRENCLAVE] and output sealed data.
    ***/
    bool processGetSecretResponse(Messages::GetSecretResponse& getSecretResponse);

    //TODO - this should be private and called by NetworkManagerClient
    vector<string> skgIncomingHandler(string v, int type);

private:
    bool obtainCertificate();
    bool readSecret();
    bool writeSecret();
    bool extractConfiguration(bb_config_t** ppBbConfig, size_t& configSize);

private:
    NetworkManagerClient *m_skgNmc = NULL;
    NetworkManagerServer *m_bbNms = NULL;
    VerificationReport m_report;
    BbEnclave* m_pEnclave;
    AttestationClient* m_pClient;
    Json::Value& m_config;
    
    sgx_ec256_public_t* p_bb_pk = NULL;
    sgx_sealed_data_t* p_sealed_k = NULL;
    sgx_sealed_data_t* p_sealed_s = NULL;


    ThcClient* m_pThcClient;
    ThcServer* m_pThcServer;
};

#endif











