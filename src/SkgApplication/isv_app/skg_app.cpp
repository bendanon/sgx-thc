#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"
#include "VerificationReport.h"
#include "Messages.pb.h"
#include "SkgServer.h"

#include "SkgEnclave.h"

void ocall_print(const char* str) {
    printf("%s\n", str);
}

int Main(int argc, char* argv[]) {
    LogBase::Inst();

    int ret = 0;

    sgx_status_t sgx_ret;
    SkgEnclave* skg_enclave = new SkgEnclave();
    if (SGX_SUCCESS != skg_enclave->createEnclave()){
        Log("createEnclave failed");
        return -1;
    }

    Messages::PkRequest pkRequest;
    Messages::CertificateMSG skgCertMsg1, skgCertMsg2;
    Messages::CertificateMSG bbCertMsg1, bbCertMsg2;
    Messages::GetSecretResponse getSecretResponse1, getSecretResponse2;

    //TODO: For now, both skg and bb are on the same machine and use the same enclave
    //for testing purposes. In the future, both will encapsulate their own enclaves
    SkgServer skgServer(skg_enclave);
    if(!skgServer.init())
        Log("SkgServer Failed to Init");

    delete skg_enclave;
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







