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
    if (SGX_SUCCESS != bb_enclave->createEnclave()) {
        Log("createEnclave failed");
        return -1;
    }

    BbClient bbClient(bb_enclave, 44444);

    while(!bbClient.hasSecret())
    {
        bbClient.obtainSecretFromSkg();        
    }
    
    #if 0
    uint8_t B_out[B_OUT_SIZE_BYTES];
    memset(B_out, 0, B_OUT_SIZE_BYTES);   
    
    uint8_t B_in[B_IN_SIZE_BYTES];          //TODO: Recieve this as input from neighbor
    memset(B_in, 0, B_IN_SIZE_BYTES);

    bbClient.execute(B_in, B_IN_SIZE_BYTES, B_out, B_OUT_SIZE_BYTES);
    Log("B_out is %s", Base64encodeUint8((uint8_t*)B_out, sizeof(B_out)));
    #endif

    //InputParser parsedInput(argc, argv);

    //Setting neighbors and input for black box
    //bbClient.processLocalInput(parsedInput);

    bbClient.acceptInputFromNeighbors();

    delete bb_enclave;
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







