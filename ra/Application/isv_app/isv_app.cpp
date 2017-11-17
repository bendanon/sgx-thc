#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"

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

    AttestationClient raClient(enclave);
    raClient.init();
    raClient.start();
    
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







