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
#include <jsoncpp/json/json.h>
#include <Enclave.h>

using namespace std;
using namespace util;

#define HASH_ALGORITHM "SHA256"

class VerificationReport {

public:
    VerificationReport();
    virtual ~VerificationReport();

    bool isValid();    
    bool fromCertMsg(Messages::CertificateMSG& certMsg, verification_report_t& report);
    bool toCertMsg(sgx_ec256_public_t* p_gb, Messages::CertificateMSG& certMsg);
    bool fromResult(vector<pair<string, string>> result);
    bool setGa(sgx_ec256_public_t* p_ga);
    bool read(std::string file);
    bool write(std::string file);

  

private:
    bool verifySignature(); 
    bool verifyCertificateChain();
    bool insertIASCertificate(Messages::CertificateMSG& certMsg);
    bool insertIASSignature(Messages::CertificateMSG& certMsg);
    bool insertIASFullResponse(Messages::CertificateMSG& certMsg);
    bool insertGa(Messages::CertificateMSG& certMsg);
    bool extractIASCertificate(Messages::CertificateMSG& certMsg);
    bool extractIASSignature(Messages::CertificateMSG& certMsg);
    bool extractIASFullResponse(Messages::CertificateMSG& certMsg);
    bool extractGa(Messages::CertificateMSG& certMsg);

    string uriDecode(string encoded);


private:
    
    bool m_isValid;
    bool m_certificateValid;
    X509* m_cert = NULL;

    /*All of those should be written to / read from drive*/
    sgx_quote_t m_quote_body;
    sgx_ec256_public_t m_ga;
    string m_x_iasreport_signature;
    string m_x_iasreport_signing_certificate;
    string m_full_response;
};

#endif











