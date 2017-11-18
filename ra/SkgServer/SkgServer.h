#ifndef SkgServer_H
#define SkgServer_H

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

class SkgServer {

public:
    SkgServer(Enclave* pEnclave);
    virtual ~SkgServer();
    
    bool obtainCertificate();

    bool processPkRequest(Messages::PkRequest pkRequest, Messages::PkResponse pkResponse);


    bool processGetSecretRequest(Messages::GetSecretRequest getSecretRequest, 
                                 Messages::GetSecretResponse getSecretResponse);

private:
    bool readCertificateFromMemory();

private:
    VerificationReport m_report;
    Enclave* m_pEnclave;
    AttestationClient* m_pClient;
};

#endif











