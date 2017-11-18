#ifndef BbClient_H
#define BbClient_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

#include "LogBase.h"
#include "../GeneralSettings.h"
#include "Enclave.h"
#include "Messages.pb.h"
#include "VerificationReport.h"
#include "AttestationClient.h"

using namespace std;
using namespace util;

class BbClient {

public:
    BbClient(Enclave* pEnclave);
    virtual ~BbClient();
    
    bool obtainCertificate();

    bool generatePkRequest(Messages::PkRequest pkRequest);


    bool processPkResponse(Messages::PkResponse pkResponse, 
                           Messages::GetSecretRequest getSecretRequest);


    bool processGetSecretResponse(Messages::GetSecretResponse getSecretResponse);

private:
    bool readCertificateFromMemory();

private:
    VerificationReport m_report;
    Enclave* m_pEnclave;
    AttestationClient* m_pClient;
};

#endif











