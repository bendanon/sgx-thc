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

using namespace std;
using namespace util;

#define SIGNATURE_LENGTH_BYTES 256

class VerificationReport {

  #define hn "SHA256"
  #define msg_dummy "{\"id\":\"195086063909628449559119570588757258481\",\"timestamp\":\"2017-12-02T08:03:14.206564\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000100000606010101010000000000000000000004000004000000020000000000000D6E9C2F2DAD7C364003C283605B14D49FF6FA7067A78EB54E62298787B5CB31B958137E8D78C4CE13D2A89FCEE5D4B5DD838CFE212F29CA0E95FE30C58F9A7AC0C0\",\"isvEnclaveQuoteBody\":\"AgAAAG4NAAAFAAQAAAAAAKx/3QbhJMVkvh5sZm978EtBxh8SbzkDNpgFR1Tmf0iaBAT/BAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAACddfArWKc1oujF/wfKlV5HmFBu6/EuKUY0Ca7IYxoZLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgJ3rS/fxX6YDoduf4eKwZCYgOpTgHlafo6pixV4QfhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwJdPcqHDLJZK72dEkW6EZe0s6fWPy+5j6uYOk6tAzbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"
  #define mlen strlen(msg_dummy)

  #define sig_base64_dummy "mj2AXJQkLJ5JWHsI8Qm/nFc6OnChy+z+8POWdRvUg6yVXU2BeWcOjZvwR8rooiNNXgbS4MxoBHX6XVMaha4CXSNxB8ZLIdb1hCcI5FsDhDp2Iljhflt4qwF735vK4nmWk/nZTQd/at1vHMij1BDSERBJatpJO+EDaYmUcrScnmdy42m2LT1MIDyh/7NwdBQAoykF8RkGL8cT279egrwdvcWMZSM8/k+Q/YsqWGvsvVRjh+/HvbbRzoHzyfzLFHiCh4wc4WJXq9CuGtwfAS2PC9xQ8BRkmgKdp92k26C7Q/htomp22KXhLZxd+Yf/gfgKU4iBoDhd0FM9blyvoyG0Xw=="

  static const char dummy_cert_buf[];

public:
    VerificationReport();
    virtual ~VerificationReport();

    bool deserialize(uint8_t* buffer);
    bool serialize(uint8_t* o_buffer);
    bool isValid();    
    bool fromMsg4(Messages::MessageMSG4& msg);
    bool fromResult(vector<pair<string, string>> result);
   
    bool read(std::string file);
    bool write(std::string file);

private:
    bool verifySignature(); 
    bool verifyCertificateChain();


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
    X509* m_cert = NULL;
};

#endif











