#include "VerificationReport.h"

VerificationReport::VerificationReport() : m_isValid(false) { }
VerificationReport::~VerificationReport() { }

bool VerificationReport::deserialize(uint8_t* buffer) {
    Log("VerificationReport::deserialize - not implemented");
    return false;
}

bool VerificationReport::serialize(uint8_t* o_buffer){
    Log("VerificationReport::serialize - not implemented");
    return false;
}

 bool VerificationReport::fromMsg4(Messages::MessageMSG4& msg) {

    //TODO - this should extract the whole response body and signature, 
    //not just report body

    uint32_t* response_body_buf = reinterpret_cast<uint32_t*>(&this->m_report_body);

    for (int i=0; i<sizeof(sgx_report_body_t)/sizeof(uint32_t); i++)
        response_body_buf[i] = msg.response_body(i);

    m_isValid=true; //TODO - this should not be the only condition for a valid report

    Log("VerificationReport::fromMsg4 - success");
    return true;
 }

 bool VerificationReport::read(std::string file){
    if(!readEncodedAssets(file, (uint8_t*)&this->m_report_body, 
                           sizeof(sgx_report_body_t), REPORT_BASE64_SIZE_BYTES))
    {
        Log("VerificationReport::read report failed");
        return false;
    }

    Log("VerificationReport::read - succeeded");
    return true;
 }

 bool VerificationReport::write(std::string file){

    if(!writeEncodedAssets(file, (uint8_t*)&this->m_report_body, 
                           sizeof(sgx_report_body_t), REPORT_BASE64_SIZE_BYTES))
    {
        Log("VerificationReport::write report failed");
        return false;
    }

    Log("VerificationReport::write - succeeded");
    return true;
 }

bool VerificationReport::isValid()
{
    return m_isValid;
}

bool VerificationReport::fromResult(vector<pair<string, string>> result)
{

    string isvEnclaveQuoteBody,
           platformInfoBlob, 
           revocationReason,
           pseManifestStatus,
           pseManifestHash,
           nonce,
           /*epidPseudonym*/
           timestamp;

    for (auto x : result) {
        if (x.first == "id") {
            m_id = x.second;
        } else if (x.first == "isvEnclaveQuoteStatus") {

            if (x.second == "OK")
                m_quoteStatus = IAS_QUOTE_OK;
            else if (x.second == "SIGNATURE_INVALID")
                m_quoteStatus = IAS_QUOTE_SIGNATURE_INVALID;
            else if (x.second == "GROUP_REVOKED")
                m_quoteStatus = IAS_QUOTE_GROUP_REVOKED;
            else if (x.second == "SIGNATURE_REVOKED")
                m_quoteStatus = IAS_QUOTE_SIGNATURE_REVOKED;
            else if (x.second == "KEY_REVOKED")
                m_quoteStatus = IAS_QUOTE_KEY_REVOKED;
            else if (x.second == "SIGRL_VERSION_MISMATCH")
                m_quoteStatus = IAS_QUOTE_SIGRL_VERSION_MISMATCH;
            else if (x.second == "GROUP_OUT_OF_DATE")
                m_quoteStatus = IAS_QUOTE_GROUP_OUT_OF_DATE;

        } else if (x.first == "isvEnclaveQuoteBody") {
            memcpy(&m_quote_body, Base64decode(x.second).c_str(), sizeof(m_quote_body));            
        } else if (x.first == "platformInfoBlob") {
            platformInfoBlob = x.second;
        } else if (x.first == "revocationReason") {
            revocationReason = x.second;
        } else if (x.first == "pseManifestStatus") {
            pseManifestStatus = x.second;
        } else if (x.first == "pseManifestHash") { 
            pseManifestHash = x.second;
        } else if (x.first == "nonce") {
            nonce = x.second;
        } else if (x.first == "timestamp") {
            timestamp = x.second;
        }
    }    
    Log("VerificationReport::fromResult - not implemented");
    return false;
}