#ifndef AttestationClient_H
#define AttestationClient_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

#include "NetworkManagerClient.h"
#include "Messages.pb.h"
#include "UtilityFunctions.h"
#include "remote_attestation_result.h"
#include "LogBase.h"
#include "../GeneralSettings.h"
#include "VerificationReport.h"
#include "Network_def.h"
#include "WebService.h"
#include "Enclave.h"


using namespace std;
using namespace util;

#define DH_SHARED_KEY_LEN 32
#define AES_CMAC_KDF_ID 0x0001
#define EC_MAC_SIZE 16

class AttestationClient {

public:
    AttestationClient(Enclave *enclave, 
                      VerificationReport& report, 
                      sgx_ec256_public_t* p_pk);

    virtual ~AttestationClient();
    int init();
    void start();
    vector<string> incomingHandler(string v, int type);

private:
    uint32_t getExtendedEPID_GID(uint32_t *extended_epid_group_id);
    sgx_status_t getEnclaveStatus();

    void assembleMSG2(Messages::MessageMSG2 msg, sgx_ra_msg2_t **pp_msg2);
    string handleMSG2(Messages::MessageMSG2 msg);
    string generateMSG1();
    bool handleMSG1(Messages::MessageMSG1 msg1, Messages::MessageMSG2 *msg2);
    bool handleMSG3(Messages::MessageMSG3 msg);
    sgx_ra_msg3_t* assembleMSG3(Messages::MessageMSG3 msg);

protected:
    Enclave *m_pEnclave = NULL;

private:
    int busy_retry_time = 4;
    VerificationReport& m_report;
    sgx_report_body_t m_sent_report_body;
    uint32_t m_extended_epid_group_id;
    WebService *ws = NULL;
    sgx_ec_key_128bit_t m_smk_key;
    sgx_ec256_public_t* m_p_pk = NULL;
    sgx_ps_sec_prop_desc_t m_ps_sec_prop;
    sgx_ec256_public_t m_ga = {{0},{0}};


};

#endif











