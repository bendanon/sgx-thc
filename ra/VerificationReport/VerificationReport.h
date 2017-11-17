#ifndef VerificationReport_H
#define VerificationReport_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>

#include "LogBase.h"
#include "../GeneralSettings.h"

using namespace std;
using namespace util;

class VerificationReport {

public:
    VerificationReport();
    virtual ~VerificationReport();

    bool deserialize(uint8_t* buffer);
    bool serialize(uint8_t* o_buffer);
    bool isValid();

private:
    bool m_isValid;
};

#endif











