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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <curl/curl.h>

using namespace std;
using namespace util;

#define SIGNATURE_LENGTH_BYTES 256
#define HASH_ALGORITHM "SHA256"

class VerificationReport {

public:
    VerificationReport();
    virtual ~VerificationReport();

    bool isValid();    
    bool fromMsg4(Messages::MessageMSG4& msg);
    bool fromResult(vector<pair<string, string>> result);

    bool verifyPublicKey(sgx_ec256_public_t& ga, sgx_ec256_public_t& gb);
   
    bool read(std::string file);
    bool write(std::string file);

private:
    bool verifySignature(); 
    bool verifyCertificateChain();
    string uriDecode(string encoded);


private:
    
    bool m_isValid;
    X509* m_cert = NULL;

    sgx_report_body_t m_report_body;  //TODO - remove
    ias_quote_status_t m_quoteStatus; //TODO - remove
    string m_id;                      //TODO - remove
    string m_location;                //TODO - remove

    /*All of those should be written to / read from drive*/
    sgx_quote_t m_quote_body;
    string m_x_iasreport_signature;
    string m_x_iasreport_signing_certificate;
    string m_full_response;
};

#endif











