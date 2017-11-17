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

bool VerificationReport::isValid()
{
    return m_isValid;
}