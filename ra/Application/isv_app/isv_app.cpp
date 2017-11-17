#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"
#include "VerificationReport.h"

int Main(int argc, char* argv[]) {
    LogBase::Inst();

    int ret = 0;


    sgx_status_t sgx_ret;
    Enclave* enclave = Enclave::getInstance();
    sgx_ret = enclave->createEnclave();
    if (sgx_ret != SGX_SUCCESS)
    {
        Log("createEnclave failed");
        return -1;
    }

    VerificationReport report;
    AttestationClient raClient(enclave, report);
    raClient.init();
    raClient.start();

    //Here I can expect report.isValid() == true

    delete enclave;

    return ret;
}


int main( int argc, char **argv ) {
    try {
        return Main(argc, argv);
    } catch (std::exception& e) {
        Log("exception: %s", e.what());
    } catch (...) {
        Log("unexpected exception") ;
    }

    return -1;
}







