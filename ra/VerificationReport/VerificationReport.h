#ifndef VerificationReport_H
#define VerificationReport_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include "sgx_report.h"

#include "LogBase.h"
#include "../GeneralSettings.h"
#include <string.h>
#include "Messages.pb.h"
#include "UtilityFunctions.h"
#include "../../thc/App/th_definitions.h"
#include "../ServiceProvider/service_provider/ias_ra.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

using namespace std;
using namespace util;

class VerificationReport {

public:
    VerificationReport();
    virtual ~VerificationReport();

    bool deserialize(uint8_t* buffer);
    bool serialize(uint8_t* o_buffer);
    bool isValid();    
    bool fromMsg4(Messages::MessageMSG4& msg);
    bool fromResult(vector<pair<string, string>> result);
    bool verifySignature();
    bool read(std::string file);
    bool write(std::string file);

private:
    bool m_isValid;
    sgx_report_body_t m_report_body;
    ias_quote_status_t m_quoteStatus;
    string m_id;
    sgx_quote_t m_quote_body;
    string m_x_iasreport_signature;
    string m_x_iasreport_signing_certificate;
    string m_location;
    string m_full_response;
};

#endif











