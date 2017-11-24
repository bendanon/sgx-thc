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