#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "AttestationClient.h"
#include "VerificationReport.h"
#include "Messages.pb.h"
#include "BbClient.h"
#include "BbEnclave.h"

void ocall_print(const char* str) {
    printf("%s\n", str);
}

int Main(int argc, char* argv[]) {
    LogBase::Inst();

    int ret = 0;

    sgx_status_t sgx_ret;
    BbEnclave* bb_enclave = new BbEnclave();
    BbEnclave* bb2_enclave = new BbEnclave();
    if (SGX_SUCCESS != bb_enclave->createEnclave() ||
        SGX_SUCCESS != bb2_enclave->createEnclave()){
        Log("createEnclave failed");
        return -1;
    }

    Messages::PkRequest pkRequest;
    Messages::CertificateMSG skgCertMsg1, skgCertMsg2;
    Messages::CertificateMSG bbCertMsg1, bbCertMsg2;
    Messages::GetSecretResponse getSecretResponse1, getSecretResponse2;


    BbClient bbClient(bb_enclave);
    BbClient bbClient2(bb2_enclave);
    
    uint8_t B_out[B_OUT_SIZE_BYTES];
    memset(B_out, 0, B_OUT_SIZE_BYTES);   

    uint8_t B_out2[B_OUT_SIZE_BYTES];
    memset(B_out2, 0, B_OUT_SIZE_BYTES); 
    
    uint8_t B_in[B_IN_SIZE_BYTES];          //TODO: Recieve this as input from neighbor
    memset(B_in, 0, B_IN_SIZE_BYTES);

    bbClient.execute(B_in, B_IN_SIZE_BYTES, B_out, B_OUT_SIZE_BYTES);
    bbClient2.execute(B_out, B_IN_SIZE_BYTES, B_out2, B_OUT_SIZE_BYTES);

    if(0==memcmp(B_in,B_out2,B_OUT_SIZE_BYTES)){
        Log("Comparison success");
    }
    else {
        Log("Comparison failed");        
    }

    delete bb_enclave;
    delete bb2_enclave;
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







