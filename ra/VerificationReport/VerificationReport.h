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
    bool read(std::string file);
    bool write(std::string file);

private:
    bool m_isValid;
    sgx_report_body_t m_report_body;
};

#endif











