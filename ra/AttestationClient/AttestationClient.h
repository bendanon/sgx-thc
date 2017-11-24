#ifndef AttestationClient_H
#define AttestationClient_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

#include "Enclave.h"
#include "NetworkManagerClient.h"
#include "Messages.pb.h"
#include "UtilityFunctions.h"
#include "remote_attestation_result.h"
#include "LogBase.h"
#include "../GeneralSettings.h"
#include "VerificationReport.h"

using namespace std;
using namespace util;

class AttestationClient {

public:
    AttestationClient(Enclave *enclave, VerificationReport& report);
    virtual ~AttestationClient();

    sgx_ra_msg3_t* getMSG3();
    int init();
    void start();
    vector<string> incomingHandler(string v, int type);

private:
    uint32_t getExtendedEPID_GID(uint32_t *extended_epid_group_id);
    sgx_status_t getEnclaveStatus();

    //void assembleAttestationMSG(Messages::MessageMSG4 msg, ra_samp_response_header_t **pp_att_msg);
    //string handleAttestationResult(Messages::MessageMSG4 msg);
    string handleMSG4(Messages::MessageMSG4 msg);
    void assembleMSG2(Messages::MessageMSG2 msg, sgx_ra_msg2_t **pp_msg2);
    string handleMSG2(Messages::MessageMSG2 msg);
    string handleMSG0Response(Messages::MessageMsg0 msg);
    string generateMSG1();
    string generateMSG0();
    //string createInitMsg(int type, string msg);
    void restart();

protected:
    Enclave *m_pEnclave = NULL;

private:
    int busy_retry_time = 4;
    NetworkManagerClient *nm = NULL;
    VerificationReport& m_report;
    sgx_report_body_t m_sent_report_body;

};

#endif











